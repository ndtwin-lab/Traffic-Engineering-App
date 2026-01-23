# Copyright (c) 2025-present
 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
 
#   http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# NDTwin core contributors (as of January 15, 2026):
#     Prof. Shie-Yuan Wang <National Yang Ming Chiao Tung University; CITI, Academia Sinica> 
#     Ms. Xiang-Ling Lin <CITI, Academia Sinica>
#     Mr. Po-Yu Juan <CITI, Academia Sinica>
#     Mr. Tsu-Li Mou <CITI, Academia Sinica> 
#     Mr. Zhen-Rong Wu <National Taiwan Normal University>
#     Mr. Ting-En Chang <University of Wisconsin, Milwaukee>
#     Mr. Yu-Cheng Chen <National Yang Ming Chiao Tung University>
    
import requests
import json
from loguru import logger
import networkx as nx
import socket, ipaddress
import time, signal, sys, threading
from datetime import datetime

ndt_url = "http://localhost:8000/ndt/"
congested_threshold = 70
idle_threshold = 30
elephant_flow_threshold = 10000000  # 10Mbps
migrate_threshold = 1.5
te_flow_entry_priority = 100
default_flow_entry_priority = 10
te_flow_entry_idle_timeout = 0
migrate_only_one_flow_per_round = False
get_graph_data_interval = 1


ecmp_group_by_switch = {}
trigger = threading.Event()


def get_graph_data_api_call():
    logger.debug("get_graph_data_api_call")
    try:
        graph_data = requests.get(ndt_url + "get_graph_data").json()
        # logger.debug(json.dumps(graph_data, indent=2))
    except Exception as e:
        logger.error(e)

    return graph_data


def get_detected_flow_data_api_call():
    try:
        flow_data = requests.get(ndt_url + "get_detected_flow_data").json()
        # logger.debug(json.dumps(flow_data, indent=2))
    except Exception as e:
        logger.error(e)

    return flow_data

def acquire_lock_api_call(ttl=300):
    logger.debug("acquire_lock_api_call")
    try:
        result = requests.post(ndt_url + "acquire_lock", json={"ttl": ttl, "type": "routing_lock"}).json()
        logger.debug(result)
        if result.get("status", None):
            logger.debug("acquire_lock_api_call succeeded")
            return True
    except Exception as e:
        logger.error(e)  
        
    return False


def release_lock_api_call():
    logger.debug("release_lock_api_call")
    try:
        result = requests.post(ndt_url + "release_lock", json={"type": "routing_lock"}).json()
        if result.get("status", None):
            logger.debug("release_lock succeeded")
            return True
    except Exception as e:
        logger.error(e)  
        
    return False


# ===== Prepare flow dict =====
def construct_flow_dict(flow_data):
    flow_data_dict = {}
    for f in flow_data:
        src_ip = f["src_ip"]
        dst_ip = f["dst_ip"]
        src_port = f["src_port"]
        dst_port = f["dst_port"]
        protocol_id = f["protocol_id"]

        flow_data_dict[(src_ip, dst_ip, src_port, dst_port, protocol_id)] = f
    return flow_data_dict


# ===== Prepare graph =====
def construct_graph(graph_data):
    DG = nx.DiGraph()

    edge_switches = []

    for e in graph_data["edges"]:
        src_dpid = e["src_dpid"]
        dst_dpid = e["dst_dpid"]
        if src_dpid == 0:
            edge_switches.append(dst_dpid)

    for n in graph_data["nodes"]:
        dpid = n.get("dpid")
        if dpid is None or dpid == 0:
            continue

        # ECMP groups normalization 
        groups = n.get("ecmp_groups", []) or []
        norm_groups = []
        for g in groups:
            members = g.get("members", [])
            port_members = [
                {"type": m.get("type"), "port_id": m.get("port_id")}
                for m in members
                if m.get("type") and m.get("port_id") is not None
            ]
            norm_groups.append({"members": port_members})

        ecmp_group_by_switch[dpid] = norm_groups

        is_up = n.get("is_up", True)
        is_enabled = n.get("is_enabled", True)

        DG.add_node(
            dpid,
            is_up=is_up,
            is_enabled=is_enabled,
            ecmp_groups=norm_groups,
        )

    # logger.debug(f"ecmp_group_by_switch {ecmp_group_by_switch}")

    for e in graph_data["edges"]:
        src_dpid = e["src_dpid"]
        dst_dpid = e["dst_dpid"]
        src_interface = e["src_interface"]
        dst_interface = e["dst_interface"]
        link_bandwidth_utilization_percent = e["link_bandwidth_utilization_percent"]
        link_bandwidth_bps = e["link_bandwidth_bps"]
        flow_set = e["flow_set"]
        left_link_bandwidth_bps = e["left_link_bandwidth_bps"]

        is_congested_link = link_bandwidth_utilization_percent > congested_threshold
        is_connected_to_host = src_dpid == 0
        is_first_layer = src_dpid in edge_switches

        DG.add_edge(
            src_dpid,
            dst_dpid,
            src_interface=src_interface,
            dst_interface=dst_interface,
            link_bandwidth_utilization_percent=link_bandwidth_utilization_percent,
            left_link_bandwidth_bps=left_link_bandwidth_bps,
            link_bandwidth_bps=link_bandwidth_bps,
            flow_set=flow_set,
            is_congested_link=is_congested_link,
            is_connected_to_host=is_connected_to_host,
            is_first_layer_link=is_first_layer,
            is_congested_link_for_three_times=False,
            link_bandwidth_utilization_percent_for_past_three_times=[],
        )
    return DG


def update_congested_link_states(old_graph, new_graph):
    for u, v, data in new_graph.edges(data=True):
        # Update edge data
        old_graph[u][v]["flow_set"] = data["flow_set"]
        old_graph[u][v]["left_link_bandwidth_bps"] = data["left_link_bandwidth_bps"]
        old_graph[u][v]["link_bandwidth_utilization_percent"] = data[
            "link_bandwidth_utilization_percent"
        ]

        if (
            len(
                old_graph[u][v][
                    "link_bandwidth_utilization_percent_for_past_three_times"
                ]
            )
            >= 3
        ):
            old_graph[u][v][
                "link_bandwidth_utilization_percent_for_past_three_times"
            ] = old_graph[u][v][
                "link_bandwidth_utilization_percent_for_past_three_times"
            ][
                1:
            ]
            old_graph[u][v][
                "link_bandwidth_utilization_percent_for_past_three_times"
            ].append(data["link_bandwidth_utilization_percent"])
        else:
            old_graph[u][v][
                "link_bandwidth_utilization_percent_for_past_three_times"
            ].append(data["link_bandwidth_utilization_percent"])

        avg_link_bandwidth_utilization_percent = sum(
            old_graph[u][v]["link_bandwidth_utilization_percent_for_past_three_times"]
        ) / len(
            old_graph[u][v]["link_bandwidth_utilization_percent_for_past_three_times"]
        )
        if avg_link_bandwidth_utilization_percent >= congested_threshold:
            old_graph[u][v]["is_congested_link_for_three_times"] = True


def fabric_subgraph(G):
    # keep only switch<->switch edges (both endpoints have dpid != 0)
    keep = []
    for u, v, d in G.edges(data=True):
        if d.get("src_dpid", u) != 0 and d.get("dst_dpid", v) != 0:
            keep.append((u, v))
    H = G.edge_subgraph(keep).copy()
    if H.has_node(0):
        H.remove_node(0)
    return H


def fabric_nodes_from_flowpath(flow_path):
    """Turn your flow_data_dict path into [src_sw, ..., dst_sw] nodes (no host node 0)."""
    nodes = []
    for hop in flow_path:
        if isinstance(hop, dict):
            n = hop.get("node") or hop.get("dpid")
        else:
            n = hop
        if n is not None and n != 0:
            nodes.append(n)
    return nodes


def find_dst_by_src_port(G, src_dpid, src_interface):
    for _, v, data in G.out_edges(src_dpid, data=True):
        if data.get("src_interface") == src_interface:
            return v


def detect_imbalance_and_migrate_one_flow(u, v, data, flow_data_dict, DG):
    src_sw = u
    elephant_flows = []
    for f in data["flow_set"]:
        src_ip = f["src_ip"]
        dst_ip = f["dst_ip"]
        src_port = f["src_port"]
        dst_port = f["dst_port"]
        protocol_id = f["protocol_number"]

        flow_key = (src_ip, dst_ip, src_port, dst_port, protocol_id)

        try:
            flow_info = flow_data_dict[flow_key]
        except KeyError:
            logger.warning("missing flow_key=%r", flow_key)
            continue

        sending_rate = flow_info["estimated_flow_sending_rate_bps_in_the_last_sec"]

        if sending_rate >= elephant_flow_threshold:
            elephant_flows.append({flow_key: sending_rate})

    if len(elephant_flows) > 0:
        # TODO[debug]: Sometimes the result is not in descending order?
        sorted(elephant_flows, key=lambda ele: elephant_flows, reverse=True)
        logger.debug(elephant_flows)

        for e in elephant_flows:
            # Check whether alternative path has more bandwidth, if so, migrate
            flow_key = next(iter(e))
            path = flow_data_dict[flow_key]["path"]
            if len(path) < 2:
                continue
            dst_sw = flow_data_dict[flow_key]["path"][-2]["node"]
            sending_rate = flow_data_dict[flow_key][
                "estimated_flow_sending_rate_bps_in_the_last_sec"
            ]

            # Get all candidate paths between src_sw & dst_sw
            logger.debug(f"src_sw {src_sw} dst_sw {dst_sw}")
            H = fabric_subgraph(DG)
            try:
                # Only get shortest path as candidate paths
                candidate_paths = list(
                    nx.all_shortest_paths(H, source=src_sw, target=dst_sw)
                )
            except nx.NetworkXNoPath:
                candidate_paths = []

            logger.debug(len(candidate_paths))
            logger.debug(candidate_paths)

            # Filter out original path
            cur_path_nodes = fabric_nodes_from_flowpath(path)
            candidate_paths = [p for p in candidate_paths if p != cur_path_nodes]

            candidate_next_hops = {p[1] for p in candidate_paths if len(p) > 1}
            logger.debug(f"candidate_next_hops {candidate_next_hops}")
            candidate_next_hops_set = set(candidate_next_hops)
            logger.debug(f"candidate_next_hops_set {candidate_next_hops_set}")

            for hop in candidate_next_hops_set:
                if hop == 0:
                    continue
                left_link_bandwidth_bps_in_candidate_next_hop = DG[src_sw][hop][
                    "left_link_bandwidth_bps"
                ]
                # Check whether migrating to the new link can get more BW
                if (
                    left_link_bandwidth_bps_in_candidate_next_hop
                    > sending_rate * migrate_threshold
                ):
                    logger.debug("find a more idle link")
                    # Migrate, install specific flow rule with idle timeout
                    # TODO: Change to match 5-tuple in HPE
                    out_port = DG[src_sw][hop]["src_interface"]
                    ipv4_dst = str(ipaddress.IPv4Address(socket.htonl(flow_key[1])))
                    install_openflow_flow_entry_json = {
                        "dpid": src_sw,
                        "priority": te_flow_entry_priority,
                        "match": {
                            "eth_type": 2048,
                            "ipv4_dst": ipv4_dst,
                        },
                        "actions": [{"port": out_port, "type": "OUTPUT"}],
                        "idle_timeout": te_flow_entry_idle_timeout,
                    }
                    requests.post(
                        ndt_url + "install_flow_entry",
                        json=install_openflow_flow_entry_json,
                    )
                    # Only migrate one flow per iteration
                    return True


def detect_imbalance_and_migrate_multiple_flows(
    u,
    v,
    data,
    install_openflow_flow_entry_json_list,
    flow_data_dict,
    DG,
    ecmp_group_by_switch=ecmp_group_by_switch,
):
    logger.debug(f"congested link {u} -> {v}")
    src_sw = u
    elephant_flows = []
    src_interface = data["src_interface"]

    logger.debug(f"len(flow_set) {len(data["flow_set"])}")
    for f in data["flow_set"]:
        src_ip = f["src_ip"]
        dst_ip = f["dst_ip"]
        src_port = f["src_port"]
        dst_port = f["dst_port"]
        protocol_id = f["protocol_number"]

        flow_key = (src_ip, dst_ip, src_port, dst_port, protocol_id)

        try:
            flow_info = flow_data_dict[flow_key]
        except KeyError:
            logger.warning("missing flow_key=%r", flow_key)
            continue

        sending_rate = flow_info["estimated_flow_sending_rate_bps_in_the_last_sec"]

        if sending_rate >= elephant_flow_threshold:
            elephant_flows.append({flow_key: sending_rate})

    logger.debug(f"len(elephant_flows) {len(elephant_flows)}")
    if len(elephant_flows) > 0:
        sorted_elephant_flows = sorted(
            elephant_flows, key=lambda ele: elephant_flows, reverse=True
        )
        logger.debug(sorted_elephant_flows)

        for flow in sorted_elephant_flows:
            # Check whether alternative ECMP group members has more bandwidth, if so, migrate
            flow_key = next(iter(flow))
            sending_rate = flow_data_dict[flow_key][
                "estimated_flow_sending_rate_bps_in_the_last_sec"
            ]

            candidate_next_hops_interfaces = []
            candidate_next_hops_dpid_set = []
            # logger.debug(f"ecmp_group_by_switch {ecmp_group_by_switch}")
            groups = ecmp_group_by_switch[src_sw]
            # logger.debug(f"groups {groups}")
            is_groups_loop_end = False
            for members in groups:
                if is_groups_loop_end:
                    break
                logger.debug(f"members {members}")
                member_list = members.get("members")
                for m in member_list:
                    if m.get("port_id") is None:
                        continue
                    if m.get("port_id") == src_interface:
                        candidate_next_hops_interfaces = [
                            ele["port_id"]
                            for ele in member_list
                            if ele.get("port_id") is not None
                            and ele.get("port_id") != src_interface
                        ]
                        is_groups_loop_end = True
                        break
            # logger.debug(f"src_interface {src_interface}")
            logger.debug(
                f"candidate_next_hops_interfaces {candidate_next_hops_interfaces}"
            )

            for candidate in candidate_next_hops_interfaces:
                # Check is_up & is_enabled
                sw_cadidate = find_dst_by_src_port(DG, src_sw, candidate)
                node_data = DG.nodes[sw_cadidate]
                if node_data.get("is_up", False) and node_data.get("is_enabled", False):
                    candidate_next_hops_dpid_set.append(
                        sw_cadidate
                    )

            # Sort candidate_next_hops_dpid_set based on left_link_bandwidth_bps in descending order
            sorted_candidates = sorted(
                candidate_next_hops_dpid_set,
                key=lambda hop: DG[src_sw][hop]["left_link_bandwidth_bps"],
                reverse=True,
            )

            for hop in sorted_candidates:
                if hop == 0 or hop == v:
                    continue
                left_link_bandwidth_bps_in_candidate_next_hop = DG[src_sw][hop][
                    "left_link_bandwidth_bps"
                ]

                link_bandwidth_utilization_percent_in_candidate_next_hop = DG[src_sw][
                    hop
                ]["link_bandwidth_utilization_percent"]

                link_bandwidth_bps = DG[src_sw][hop]["link_bandwidth_bps"]

                logger.debug(
                    f"link_bandwidth_utilization_percent in original congested link {data["link_bandwidth_utilization_percent"]}"
                )
                logger.debug(
                    f"link_bandwidth_utilization_percent_in_candidate_next_hop {link_bandwidth_utilization_percent_in_candidate_next_hop}"
                )
                logger.debug(
                    f"left_link_bandwidth_bps_in_candidate_next_hop {left_link_bandwidth_bps_in_candidate_next_hop}"
                )
                logger.debug(f"sending_rate {sending_rate}")
                # Check whether the link to candidate next hop is idle & whether migrating to the new link can get more BW
                if (
                    (100 - link_bandwidth_utilization_percent_in_candidate_next_hop)
                    >= idle_threshold
                    and left_link_bandwidth_bps_in_candidate_next_hop
                    > sending_rate * migrate_threshold
                    and data["link_bandwidth_utilization_percent"]
                    > link_bandwidth_utilization_percent_in_candidate_next_hop
                ):
                    logger.debug("find a more idle link")
                    # Migrate, install specific flow rule with idle timeout
                    # TODO: Change to match 5-tuple in HPE
                    out_port = DG[src_sw][hop]["src_interface"]
                    ipv4_dst = str(ipaddress.IPv4Address(socket.htonl(flow_key[1])))
                    
                    # TODO: Change to mod
                    # install_openflow_flow_entry_json_list.append(
                    #     {
                    #         "dpid": src_sw,
                    #         "priority": te_flow_entry_priority,
                    #         "match": {
                    #             "eth_type": 2048,
                    #             "ipv4_dst": ipv4_dst,
                    #         },
                    #         "actions": [{"port": out_port, "type": "OUTPUT"}],
                    #         "idle_timeout": te_flow_entry_idle_timeout,
                    #     }
                    # )
                    
                    install_openflow_flow_entry_json_list.append(
                        {
                            "dpid": src_sw,
                            "priority": default_flow_entry_priority,
                            "match": {
                                "eth_type": 2048,
                                "ipv4_dst": ipv4_dst,
                            },
                            "actions": [{"port": out_port, "type": "OUTPUT"}],

                        }
                    )

                    logger.debug(
                        f"left_link_bandwidth_bps(bf) {DG[src_sw][hop]["left_link_bandwidth_bps"]}"
                    )
                    logger.debug(
                        f"link_bandwidth_utilization_percent(bf) {DG[src_sw][hop]["link_bandwidth_utilization_percent"]}"
                    )
                    # Subtract sending rate of migrated elephant flow from left link BW of idle link
                    DG[src_sw][hop]["left_link_bandwidth_bps"] = (
                        left_link_bandwidth_bps_in_candidate_next_hop - sending_rate
                    )
                    DG[src_sw][hop]["link_bandwidth_utilization_percent"] = (
                        link_bandwidth_utilization_percent_in_candidate_next_hop
                        + (sending_rate / link_bandwidth_bps) * 100
                    )
                    data["link_bandwidth_utilization_percent"] = (
                        data["link_bandwidth_utilization_percent"]
                        - (sending_rate / link_bandwidth_bps) * 100
                    )
                    logger.debug(
                        f"left_link_bandwidth_bps(af) {DG[src_sw][hop]["left_link_bandwidth_bps"]}"
                    )
                    logger.debug(
                        f"link_bandwidth_utilization_percent(af) {DG[src_sw][hop]["link_bandwidth_utilization_percent"]}"
                    )
                    break


def run_te(DG):
    flow_data = get_detected_flow_data_api_call()
    flow_dict = construct_flow_dict(flow_data)

    if migrate_only_one_flow_per_round:
        logger.debug("check congested links that are not in first layer")
        for u, v, data in DG.edges(data=True):
            is_congested_link = data["is_congested_link_for_three_times"]
            if is_congested_link:
                r = detect_imbalance_and_migrate_one_flow(u, v, data)
                if r:
                    release_lock_api_call()
                    return
    else:
        install_openflow_flow_entry_json_list = []

        logger.debug("check congested links that are not in first layer")
        for u, v, data in DG.edges(data=True):
            # logger.debug(f"link_bandwidth_utilization_percent_for_past_three_times {data["link_bandwidth_utilization_percent_for_past_three_times"]}")
            is_congested_link = data["is_congested_link_for_three_times"]
            if is_congested_link:
                detect_imbalance_and_migrate_multiple_flows(
                    u, v, data, install_openflow_flow_entry_json_list, flow_dict, DG
                )

        logger.info(f"{len(install_openflow_flow_entry_json_list)} entries are added")
        
        # TODO: Change to mod
        if len(install_openflow_flow_entry_json_list) > 0:
            # requests.post(
            #     ndt_url
            #     + "install_flow_entries_modify_flow_entries_and_delete_flow_entries",
            #     json={"install_flow_entries": install_openflow_flow_entry_json_list},
            # )
            
            requests.post(
                ndt_url
                + "install_flow_entries_modify_flow_entries_and_delete_flow_entries",
                json={"modify_flow_entries": install_openflow_flow_entry_json_list},
            )

            for entry in install_openflow_flow_entry_json_list:
                logger.debug(f"{entry}")
                
    release_lock_api_call()

    return


def enter_listener():
    try:
        while True:
            input("Press Enter to run (Ctrl+C to quit)…")
            trigger.set()
    except (EOFError, KeyboardInterrupt):
        pass


def ask_mode():
    print("Select TE mode:")
    print("  1) Execute run_te() when you press Enter")
    print("  2) Execute run_te() periodically (e.g., every 5 seconds)")
    choice = input("Enter 1 or 2 [default 1]: ").strip() or "1"
    if choice not in {"1", "2"}:
        choice = "1"

    te_interval = 5.0
    if choice == "2":
        s = input("How many seconds between TE runs? [default 5]: ").strip()
        if s:
            try:
                te_interval = float(s)
            except ValueError:
                print("Invalid number, using 5 seconds.")
                te_interval = 5.0
    return choice, te_interval


def record_link_utilization(graph_data, filename, record_count):

    extracted_edge_data = []
    for e in graph_data["edges"]:
        src_dpid = e["src_dpid"]
        dst_dpid = e["dst_dpid"]
        src_interface = e["src_interface"]
        dst_interface = e["dst_interface"]
        link_bandwidth_utilization_percent = e["link_bandwidth_utilization_percent"]

        extracted_edge_data.append(
            {
                "src_dpid": src_dpid,
                "dst_dpid": dst_dpid,
                "src_interface": src_interface,
                "dst_interface": dst_interface,
                "link_bandwidth_utilization_percent": link_bandwidth_utilization_percent,
            }
        )

    with open("./te_results/"+filename, "a") as f:
        j = {str(record_count): extracted_edge_data}
        f.write(json.dumps(j)+"\n")
        
        record_count=record_count+1
        return record_count


def main():
    mode, te_interval = ask_mode()

    filename = datetime.now().strftime("%Y-%m-%d-%H-%M-%S") + ".json"
    record_count = 0

    # kick off Enter listener only in mode 1
    if mode == "1":
        t = threading.Thread(target=enter_listener, daemon=True)
        t.start()

    # initial graph
    init = get_graph_data_api_call()
    
    # Record
    record_count=record_link_utilization(init, filename, record_count)
    
    if not init:
        logger.warning("Initial get_graph_data_api_call() returned no data.")
    old_graph = construct_graph(init)

    # schedulers
    graph_interval = float(get_graph_data_interval)
    next_graph = time.monotonic()  # next time to refresh graph
    next_te = time.monotonic() + te_interval if mode == "2" else None

    while True:
        now = time.monotonic()
        # compute timeouts for the next event
        t_graph = max(0.0, next_graph - now)
        t_te = max(0.0, next_te - now) if next_te is not None else None

        # smallest timeout among pending events
        if t_te is None:
            timeout = t_graph
        else:
            timeout = min(t_graph, t_te)

        if mode == "1":
            # wait can be interrupted early by Enter
            fired = trigger.wait(timeout)
            if fired:
                trigger.clear()
                # immediate TE run
                try:
                    if acquire_lock_api_call():
                        run_te(old_graph)
                except Exception:
                    logger.exception("run_te failed (mode 1)")
                # do not change next_graph; keep cadence
                continue
        else:
            # mode 2: no Enter listener; just sleep until the next event
            time.sleep(timeout)

        # handle due events
        now = time.monotonic()

        # periodic graph refresh
        if now >= next_graph:
            try:
                data = get_graph_data_api_call()
                
                # Record
                record_count=record_link_utilization(data, filename, record_count)
                
                if data:  # keep old_graph if fetch failed
                    new_graph = construct_graph(data)
                    update_congested_link_states(old_graph, new_graph)
            except Exception:
                logger.exception("graph refresh failed")
            # fixed-rate schedule (no drift)
            while next_graph <= now:
                next_graph += graph_interval

        # periodic TE (mode 2)
        if next_te is not None and now >= next_te:
            try:
                if acquire_lock_api_call():
                    run_te(old_graph)
            except Exception:
                logger.exception("run_te failed (mode 2)")
            # fixed-rate schedule
            while next_te <= now:
                next_te += te_interval


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nExit!")
        sys.exit(0)
