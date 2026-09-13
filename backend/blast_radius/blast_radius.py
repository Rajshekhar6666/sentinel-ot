from collections import deque


def calculate_blast_radius(graph, start_node, critical_nodes, max_hops=3):
    """
    Find critical nodes reachable from suspicious node
    within a limited number of hops.
    """

    queue = deque([(start_node, 0)])
    visited = {start_node}
    reachable_critical = []

    while queue:
        current_node, hops = queue.popleft()

        if hops > max_hops:
            continue

        if current_node in critical_nodes and current_node != start_node:
            reachable_critical.append({
                "node": current_node,
                "hops": hops
            })

        for neighbour in graph.get(current_node, []):
            if neighbour not in visited:
                visited.add(neighbour)
                queue.append((neighbour, hops + 1))

    # Simple blast radius score
    if not critical_nodes:
        score = 0.0
    else:
        score = min(
            len(reachable_critical) / len(critical_nodes),
            1.0
        )

    return {
        "blast_radius_score": round(score, 2),
        "reachable_critical_nodes": reachable_critical
    }