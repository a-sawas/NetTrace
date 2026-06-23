"""
graph_builder.py
Stage 3: Build a weighted directed graph from classified connections.


  - When multiple connections share the same (src, dst) pair (e.g. port 445
    AND port 135 both from .130 → .133), only the HIGHEST-RISK one is kept
    in the adjacency list per pair.  This prevents Dijkstra from accidentally
    taking a low-risk duplicate edge when a higher-risk edge exists.

Nodes  = IP addresses
Edges  = network connections between IPs
Weight = ((100 - risk_score) / 100) ** 2
  → High risk (91/100) → weight 0.0081  (Dijkstra prefers it)
  → Low  risk (12/100) → weight 0.7744  (Dijkstra avoids it)
"""


def build_graph(connections):
    
    # best_edge[(src, dst)] = edge_data with highest risk_score
    best_edge = {}
    nodes     = set()

    for conn in connections:
        src  = conn["src"]
        dst  = conn["dst"]
        risk = conn.get("risk_score", 50)

        nodes.add(src)
        nodes.add(dst)

        key = (src, dst)
        if key not in best_edge or risk > best_edge[key]["risk_score"]:
            weight = round(((100 - risk) / 100) ** 2, 4)
            best_edge[key] = {
                "weight":     weight,
                "risk_score": risk,
                "label":      conn.get("label", "unknown"),
                "port":       conn.get("port", 0),
                "protocol":   conn.get("protocol", ""),
            }

    # Build adjacency list from de-duplicated best edges
    graph = {}
    for (src, dst), edge_data in best_edge.items():
        if src not in graph:
            graph[src] = []
        graph[src].append((dst, edge_data["weight"], edge_data))

    total_edges = sum(len(v) for v in graph.values())
    print(f"[Graph] Built graph: {len(nodes)} nodes, {total_edges} edges "
          f"(de-duplicated from {len(connections)} flows).")
    return graph, nodes


def get_adjacency_for_display(connections):
    
    best = {}
    for conn in connections:
        src   = conn["src"]
        dst   = conn["dst"]
        risk  = conn.get("risk_score", 50)
        key   = (src, dst)
        if key not in best or risk > best[key][3]:
            weight = round(((100 - risk) / 100) ** 2, 4)
            best[key] = (src, dst, weight, risk, conn.get("label", "unknown"))

    return list(best.values())