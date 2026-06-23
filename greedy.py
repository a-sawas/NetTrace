"""
greedy.py
Stage 5: Greedy algorithm to find the CRITICAL NODE.

— Multi-path support:
  - find_critical_node()  accepts either a single path (list of str)
    OR multiple paths (list of lists).  It scores nodes across ALL paths.
  - get_suspicious_nodes() similarly accepts both formats.
"""


def _flatten_paths(attack_paths):
    """
    Normalise input: accepts either
      - a single path  (list of str)
      - multiple paths (list of list of str)
    Returns a list of paths (always list-of-lists) and a flat set of all nodes.
    """
    if not attack_paths:
        return [], set()
    if isinstance(attack_paths[0], str):
        # Single path passed in
        paths = [attack_paths]
    else:
        paths = attack_paths
    all_nodes = {node for path in paths for node in path}
    return paths, all_nodes


def find_critical_node(attack_paths, connections, risk_threshold=70):
    """
    Identifies the single most critical intermediate node across ALL attack paths.

    Args:
        attack_paths    (list of str  OR  list of list of str)
        connections     (list of dict): all classified connections
        risk_threshold  (int): minimum risk_score to count as high-risk

    Returns:
        critical_node (str or None)
        scores        (dict): { ip: high_risk_connection_count }
    """
    paths, all_nodes = _flatten_paths(attack_paths)

   
    attacker = paths[0][0] if paths else None
    terminal_nodes = {path[-1] for path in paths}   # all targets

    candidates = set()
    for path in paths:
        # Intermediate = not the attacker, not any terminal
        for node in path[1:-1]:
            candidates.add(node)

   
    for path in paths:
        for node in path[1:]:
            if node not in terminal_nodes or node in candidates:
                candidates.add(node)

    # Remove the attacker just in case
    candidates.discard(attacker)

    if not candidates:
        print("[Greedy] No intermediate nodes — path too short.")
        return None, {}

    scores = {node: 0 for node in candidates}

    for conn in connections:
        if conn.get("risk_score", 0) < risk_threshold:
            continue
        src = conn["src"]
        dst = conn["dst"]
        for node in candidates:
            if node == src or node == dst:
                scores[node] += 1

    if not scores or max(scores.values()) == 0:
        print("[Greedy] No high-risk connections through any intermediate node.")
        return None, {}

    critical_node = max(scores, key=scores.get)
    print(f"[Greedy] Critical node: {critical_node}  (score: {scores[critical_node]})")
    return critical_node, scores


def get_suspicious_nodes(connections, attack_paths, risk_threshold=60):
    """
    Returns a set of IPs involved in high-risk connections that are NOT
    already on any attack path (those get their own red colour).

    Args:
        attack_paths  (list of str  OR  list of list of str)
    """
    _, attack_set = _flatten_paths(attack_paths)

    suspicious = set()
    for conn in connections:
        if conn.get("risk_score", 0) >= risk_threshold:
            if conn["src"] not in attack_set:
                suspicious.add(conn["src"])
            if conn["dst"] not in attack_set:
                suspicious.add(conn["dst"])
    return suspicious