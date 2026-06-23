"""
dijkstra.py
Stage 4: Dijkstra's algorithm implemented FROM SCRATCH using a min-heap.

Multi-path support:
  - find_attack_paths() returns ALL high-risk paths from the attacker,
    not just one. Each victim with high incoming risk gets its own path.

"""

import heapq


def dijkstra(graph, source):
    """
    Runs Dijkstra's algorithm from the source node across the graph.

    Returns:
        distances (dict): { node: minimum_total_weight_from_source }
        previous  (dict): { node: previous_node_on_best_path }
        edge_used (dict): { node: edge_data_used_to_reach_it }
    """
    distances = {}
    previous  = {}
    edge_used = {}

    for node in graph:
        distances[node] = float('inf')
        previous[node]  = None
        edge_used[node] = None
        for (dst, _, _) in graph[node]:
            if dst not in distances:
                distances[dst] = float('inf')
                previous[dst]  = None
                edge_used[dst] = None

    distances[source] = 0.0
    heap = [(0.0, source)]
    visited = set()

    while heap:
        current_cost, current_node = heapq.heappop(heap)

        if current_node in visited:
            continue
        visited.add(current_node)

        for (neighbor, weight, edge_data) in graph.get(current_node, []):
            if neighbor in visited:
                continue
            new_cost = current_cost + weight
            if new_cost < distances.get(neighbor, float('inf')):
                distances[neighbor] = new_cost
                previous[neighbor]  = current_node
                edge_used[neighbor] = edge_data
                heapq.heappush(heap, (new_cost, neighbor))

    return distances, previous, edge_used


def reconstruct_path(previous, edge_used, source, target):
    """
    Walks backwards through 'previous' to rebuild the full attack path.

    Returns:
        path       (list of str): ordered IPs from source → target
        path_edges (list of dict): edge metadata for each hop
    """
    path       = []
    path_edges = []
    current    = target

    while current is not None:
        path.append(current)
        if edge_used.get(current):
            path_edges.append(edge_used[current])
        current = previous.get(current)

    path.reverse()
    path_edges.reverse()

    if not path or path[0] != source:
        return [], []

    return path, path_edges


def is_routable(ip):
    """
    Returns True only if an IP is a real, routable unicast address.
    Filters out multicast, loopback, link-local, broadcast, unspecified.
    """
    try:
        parts  = ip.split(".")
        if len(parts) != 4:
            return False
        first  = int(parts[0])
        second = int(parts[1])
    except (ValueError, AttributeError):
        return False

    if first >= 224:                    return False  # multicast + broadcast
    if first == 127:                    return False  # loopback
    if first == 0:                      return False  # unspecified
    if first == 169 and second == 254:  return False  # link-local
    if ip == "255.255.255.255":         return False  # broadcast

    return True


def is_internal(ip):
    """Returns True for RFC-1918 private addresses."""
    return (
        ip.startswith("10.")       or
        ip.startswith("192.168.")  or
        any(ip.startswith(f"172.{x}.") for x in range(16, 32))
    )



# MAIN PUBLIC API

def find_attack_paths(graph, connections, risk_threshold=60):
    """
    Finds ALL high-risk attack paths from the attacker to every identified victim.

    This is the multi-path API.  Returns:
        all_paths   (list of lists): each element is an ordered list of IPs
        all_edges   (list of lists): edge metadata per path (parallel to all_paths)
        source      (str): attacker IP
        targets     (list of str): all victim IPs found
    """
    # 1. Collect & filter IPs 
    all_ips      = set()
    for conn in connections:
        all_ips.add(conn["src"])
        all_ips.add(conn["dst"])

    routable_ips  = {ip for ip in all_ips if is_routable(ip)}

    if not routable_ips:
        print("[Dijkstra] No routable IPs found.")
        return [], [], "", []

    external_ips  = {ip for ip in routable_ips if not is_internal(ip)}
    internal_ips  = {ip for ip in routable_ips if is_internal(ip)}

    # ── 2. Score every routable IP
    # outgoing_risk counts ALL outgoing connections (attacker sends everything).
    # incoming_risk counts ONLY connections to service ports (dst_port < 10000).
    # This prevents response/ACK packets on ephemeral ports (49xxx, etc.) from
    # inflating the attacker's incoming score and misidentifying it as a victim.
    outgoing_risk = {ip: 0 for ip in routable_ips}
    incoming_risk = {ip: 0 for ip in routable_ips}

    for conn in connections:
        src  = conn["src"]
        dst  = conn["dst"]
        risk = conn.get("risk_score", 0)
        port = conn.get("port", 0)
        if src in routable_ips and dst in routable_ips:
            outgoing_risk[src] += risk
            if port < 10000:          # service ports only — not ephemeral responses
                incoming_risk[dst] += risk


    if external_ips:
        source = max(external_ips, key=lambda ip: outgoing_risk[ip])
    else:
        zero_incoming = {ip for ip in internal_ips
                         if incoming_risk.get(ip, 0) == 0 and outgoing_risk.get(ip, 0) > 0}
        if zero_incoming:
            source = max(zero_incoming, key=lambda ip: outgoing_risk[ip])
        else:
            source = max(internal_ips,
                         key=lambda ip: outgoing_risk[ip] - incoming_risk.get(ip, 0))

    print(f"[Dijkstra] Source (attacker): {source}")

    #  3. Run Dijkstra once from source 
    distances, previous, edge_used = dijkstra(graph, source)

   
    candidate_targets = {
        ip for ip in routable_ips
        if ip != source and distances.get(ip, float('inf')) < float('inf')
    }

    
    internal_candidates = {ip for ip in candidate_targets if is_internal(ip)}
    pool = internal_candidates if internal_candidates else candidate_targets

    if not pool:
        print("[Dijkstra] No reachable targets found.")
        return [], [], source, []

   
    high_risk_targets = {
        ip for ip in pool
        if incoming_risk.get(ip, 0) >= risk_threshold
    }

    
    best_fallback = max(pool, key=lambda ip: incoming_risk.get(ip, 0))
    if not high_risk_targets:
        high_risk_targets = {best_fallback}
    else:
        
        high_risk_targets.add(best_fallback)

    # 4. Reconstruct one path per target 
    all_paths  = []
    all_edges  = []
    targets    = []

    for t in sorted(high_risk_targets):          # sorted for determinism
        path, path_edges = reconstruct_path(previous, edge_used, source, t)
        if path:
            all_paths.append(path)
            all_edges.append(path_edges)
            targets.append(t)
            print(f"[Dijkstra] Attack path → {t}: {' → '.join(path)}")

    if not all_paths:
        print("[Dijkstra] No paths could be reconstructed.")

    return all_paths, all_edges, source, targets


def find_attack_path(graph, connections):
    
    all_paths, all_edges, source, targets = find_attack_paths(graph, connections)

    if not all_paths:
        return [], [], source, ""

   
    best_idx  = max(range(len(all_paths)), key=lambda i: len(all_paths[i]))
    target    = targets[best_idx] if best_idx < len(targets) else ""

    return all_paths[best_idx], all_edges[best_idx], source, target