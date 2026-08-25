// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Unpacking of a saga DAG into an ordered, indented list of nodes for display.
//!
//! Sagas are represented server-side by steno's `SagaDag`, which serializes as
//! a [petgraph](https://docs.rs/petgraph) directed graph. This module parses
//! that JSON and flattens it into a linear list suitable for a left-hand node
//! pane, while preserving the branching structure through indentation:
//!
//! - A node fans **out** (has more than one child) → each child is indented one
//!   level deeper than the parent.
//! - A node fans **in** (has more than one parent) → it is unindented back one
//!   level from its parents.
//!
//! Nodes are emitted in a topological order that keeps parallel branches
//! grouped together (a depth-first walk that only emits a node once all of its
//! parents have been emitted).

use serde::Deserialize;
use std::collections::HashSet;

/// The kind of a saga DAG node, used for display styling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeKind {
    Start,
    End,
    Action,
    Constant,
    SubsagaStart,
    SubsagaEnd,
}

/// A single node in the flattened saga DAG.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DagNode {
    /// The node's index in the DAG. This matches the `node_id` carried by saga
    /// events, allowing events to be associated with a node.
    pub index: usize,
    /// A human-readable label for the node.
    pub label: String,
    /// The kind of node.
    pub kind: NodeKind,
    /// The indentation level reflecting the node's position in the branching
    /// structure (0 for the trunk).
    pub indent: usize,
}

// ---------------------------------------------------------------------------
// Raw deserialization structures mirroring steno's `SagaDag` serialization.
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct RawDag {
    graph: RawGraph,
    #[serde(default)]
    start_node: u32,
}

#[derive(Debug, Deserialize)]
struct RawGraph {
    nodes: Vec<RawNode>,
    #[serde(default)]
    node_holes: Vec<u32>,
    #[serde(default)]
    edges: Vec<RawEdge>,
}

/// A petgraph edge, serialized as `[source, target, weight]`. The weight for a
/// saga DAG is `()`, which serializes as `null`; we only care about the
/// endpoints.
#[derive(Debug, Deserialize)]
struct RawEdge(u32, u32, #[allow(dead_code)] serde_json::Value);

/// The internal saga node representation. Field sets mirror steno's
/// `InternalNode`; unknown fields are ignored.
#[derive(Debug, Deserialize)]
enum RawNode {
    Start {},
    End,
    Action { name: String, label: String },
    Constant { name: String },
    SubsagaStart { saga_name: String },
    SubsagaEnd { name: String },
}

impl RawNode {
    fn describe(&self) -> (NodeKind, String) {
        match self {
            RawNode::Start {} => (NodeKind::Start, "Start".to_string()),
            RawNode::End => (NodeKind::End, "End".to_string()),
            RawNode::Action { name, label } => {
                let text = if !label.is_empty() { label } else { name };
                (NodeKind::Action, text.clone())
            }
            RawNode::Constant { name } => (NodeKind::Constant, name.clone()),
            RawNode::SubsagaStart { saga_name } => {
                (NodeKind::SubsagaStart, format!("{saga_name} (subsaga)"))
            }
            RawNode::SubsagaEnd { name } => (NodeKind::SubsagaEnd, name.clone()),
        }
    }
}

/// Parse a serialized saga DAG and flatten it into an ordered, indented list of
/// nodes.
pub fn unpack_dag(dag: &serde_json::Value) -> anyhow::Result<Vec<DagNode>> {
    let raw: RawDag = serde_json::from_value(dag.clone())?;
    Ok(order_nodes(raw))
}

fn order_nodes(raw: RawDag) -> Vec<DagNode> {
    let holes: HashSet<u32> = raw.graph.node_holes.iter().copied().collect();
    let total = raw.graph.nodes.len() + holes.len();

    // Map the compact `nodes` array back onto the actual node indices,
    // accounting for any holes left by removed nodes. For saga DAGs there are
    // typically no holes, in which case this is an identity mapping.
    let mut node_at: Vec<Option<RawNode>> = (0..total).map(|_| None).collect();
    {
        let mut actual = 0usize;
        for node in raw.graph.nodes {
            while (actual as u32) < total as u32 && holes.contains(&(actual as u32)) {
                actual += 1;
            }
            if actual < total {
                node_at[actual] = Some(node);
            }
            actual += 1;
        }
    }

    // Build adjacency lists from the edge list.
    let mut out_edges: Vec<Vec<usize>> = vec![Vec::new(); total];
    let mut in_edges: Vec<Vec<usize>> = vec![Vec::new(); total];
    for RawEdge(src, tgt, _) in &raw.graph.edges {
        let (s, t) = (*src as usize, *tgt as usize);
        if s < total && t < total {
            out_edges[s].push(t);
            in_edges[t].push(s);
        }
    }
    let in_degree: Vec<usize> = in_edges.iter().map(Vec::len).collect();

    let order = topological_order(
        total,
        &node_at,
        &out_edges,
        &in_degree,
        raw.start_node as usize,
    );
    let indent = compute_indent(&order, &in_edges, &out_edges);

    order
        .into_iter()
        .filter_map(|i| {
            node_at[i].as_ref().map(|node| {
                let (kind, label) = node.describe();
                DagNode {
                    index: i,
                    label,
                    kind,
                    indent: indent[i],
                }
            })
        })
        .collect()
}

/// Produce a topological ordering that keeps parallel branches grouped.
///
/// A node is only emitted once all of its parents have been emitted; among
/// ready nodes we proceed depth-first so that a branch is laid out contiguously
/// before its sibling branches.
fn topological_order(
    total: usize,
    node_at: &[Option<RawNode>],
    out_edges: &[Vec<usize>],
    in_degree: &[usize],
    start: usize,
) -> Vec<usize> {
    let mut order = Vec::new();
    let mut emitted = vec![false; total];
    let mut parents_seen = vec![0usize; total];

    // Seed the traversal with every node that has no incoming edges, ensuring
    // the declared start node is visited first.
    let mut roots: Vec<usize> = (0..total)
        .filter(|&i| node_at[i].is_some() && in_degree[i] == 0)
        .collect();
    roots.sort_by_key(|&i| (i != start, i));

    let mut stack: Vec<usize> = Vec::new();
    for &root in roots.iter().rev() {
        stack.push(root);
    }

    while let Some(node) = stack.pop() {
        if emitted[node] || node_at[node].is_none() {
            continue;
        }
        // Not all parents have been emitted yet; this node will be re-pushed
        // when its remaining parents are emitted.
        if parents_seen[node] < in_degree[node] {
            continue;
        }

        emitted[node] = true;
        order.push(node);

        for &child in &out_edges[node] {
            parents_seen[child] += 1;
        }
        // Push children in reverse so the first child is processed first.
        for &child in out_edges[node].iter().rev() {
            if !emitted[child] {
                stack.push(child);
            }
        }
    }

    // Defensive: append any nodes not reached above (e.g. malformed graphs or
    // cycles) in index order so nothing is silently dropped.
    for (i, present) in node_at.iter().enumerate() {
        if present.is_some() && !emitted[i] {
            order.push(i);
        }
    }

    order
}

/// Compute the indentation level for each node based on fan-out/fan-in.
fn compute_indent(
    order: &[usize],
    in_edges: &[Vec<usize>],
    out_edges: &[Vec<usize>],
) -> Vec<usize> {
    let mut indent = vec![0usize; in_edges.len()];

    // `order` is topological, so every parent's indent is known before we reach
    // a node.
    for &node in order {
        let parents = &in_edges[node];
        indent[node] = match parents.len() {
            0 => 0,
            1 => {
                let parent = parents[0];
                if out_edges[parent].len() > 1 {
                    // Parent fanned out; this node is one parallel branch.
                    indent[parent] + 1
                } else {
                    indent[parent]
                }
            }
            _ => {
                // Fan-in: return to one level shallower than the branches.
                let min_parent = parents.iter().map(|&p| indent[p]).min().unwrap_or(0);
                min_parent.saturating_sub(1)
            }
        };
    }

    indent
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Build a DAG JSON value from a list of nodes and edges.
    fn dag(nodes: Vec<serde_json::Value>, edges: Vec<(u32, u32)>, start: u32) -> serde_json::Value {
        json!({
            "saga_name": "test",
            "graph": {
                "nodes": nodes,
                "node_holes": [],
                "edge_property": "directed",
                "edges": edges
                    .into_iter()
                    .map(|(s, t)| json!([s, t, null]))
                    .collect::<Vec<_>>(),
            },
            "start_node": start,
            "end_node": 0,
        })
    }

    fn action(label: &str) -> serde_json::Value {
        json!({ "Action": { "name": label, "label": label, "action_name": label } })
    }

    #[test]
    fn linear_saga_has_no_indentation() {
        // Start -> A -> B -> End
        let value = dag(
            vec![
                json!({ "Start": { "params": null } }),
                action("a"),
                action("b"),
                json!("End"),
            ],
            vec![(0, 1), (1, 2), (2, 3)],
            0,
        );

        let nodes = unpack_dag(&value).unwrap();
        let labels: Vec<_> = nodes.iter().map(|n| (n.label.as_str(), n.indent)).collect();
        assert_eq!(labels, vec![("Start", 0), ("a", 0), ("b", 0), ("End", 0)]);
    }

    #[test]
    fn fan_out_indents_parallel_branches() {
        // Start -> A ; A fans out to B and C ; B,C fan in to D -> End
        let value = dag(
            vec![
                json!({ "Start": { "params": null } }), // 0
                action("a"),                            // 1
                action("b"),                            // 2
                action("c"),                            // 3
                action("d"),                            // 4
                json!("End"),                           // 5
            ],
            vec![(0, 1), (1, 2), (1, 3), (2, 4), (3, 4), (4, 5)],
            0,
        );

        let nodes = unpack_dag(&value).unwrap();
        let by_label: std::collections::HashMap<_, _> =
            nodes.iter().map(|n| (n.label.clone(), n.indent)).collect();

        assert_eq!(by_label["Start"], 0);
        assert_eq!(by_label["a"], 0);
        // Parallel branches are indented.
        assert_eq!(by_label["b"], 1);
        assert_eq!(by_label["c"], 1);
        // Fan-in returns to the trunk.
        assert_eq!(by_label["d"], 0);
        assert_eq!(by_label["End"], 0);

        // Parallel branches are grouped: both b and c appear before d.
        let pos = |label: &str| nodes.iter().position(|n| n.label == label).unwrap();
        assert!(pos("b") < pos("d"));
        assert!(pos("c") < pos("d"));
    }

    #[test]
    fn nested_fan_out_increases_indentation() {
        // Start(0) -> A(1)
        // A fans out to B(2) and C(3)
        // B fans out to D(4) and E(5); D,E fan in to F(6)
        // C -> G(7)
        // F,G fan in to H(8) -> End(9)
        let value = dag(
            vec![
                json!({ "Start": { "params": null } }), // 0
                action("a"),                            // 1
                action("b"),                            // 2
                action("c"),                            // 3
                action("d"),                            // 4
                action("e"),                            // 5
                action("f"),                            // 6
                action("g"),                            // 7
                action("h"),                            // 8
                json!("End"),                           // 9
            ],
            vec![
                (0, 1),
                (1, 2),
                (1, 3),
                (2, 4),
                (2, 5),
                (4, 6),
                (5, 6),
                (3, 7),
                (6, 8),
                (7, 8),
                (8, 9),
            ],
            0,
        );

        let nodes = unpack_dag(&value).unwrap();
        let by_label: std::collections::HashMap<_, _> =
            nodes.iter().map(|n| (n.label.clone(), n.indent)).collect();

        assert_eq!(by_label["a"], 0);
        assert_eq!(by_label["b"], 1);
        assert_eq!(by_label["c"], 1);
        assert_eq!(by_label["d"], 2);
        assert_eq!(by_label["e"], 2);
        assert_eq!(by_label["f"], 1);
        assert_eq!(by_label["g"], 1);
        assert_eq!(by_label["h"], 0);
    }

    #[test]
    fn node_index_matches_position() {
        let value = dag(
            vec![
                json!({ "Start": { "params": null } }),
                action("a"),
                json!("End"),
            ],
            vec![(0, 1), (1, 2)],
            0,
        );
        let nodes = unpack_dag(&value).unwrap();
        assert_eq!(nodes[0].index, 0);
        assert_eq!(nodes.iter().find(|n| n.label == "a").unwrap().index, 1);
    }

    #[test]
    fn subsaga_nodes_are_labelled() {
        let value = dag(
            vec![
                json!({ "Start": { "params": null } }),
                json!({ "SubsagaStart": { "saga_name": "inner", "params_node_name": "p" } }),
                json!({ "SubsagaEnd": { "name": "inner_end" } }),
                json!("End"),
            ],
            vec![(0, 1), (1, 2), (2, 3)],
            0,
        );
        let nodes = unpack_dag(&value).unwrap();
        assert_eq!(nodes[1].label, "inner (subsaga)");
        assert_eq!(nodes[1].kind, NodeKind::SubsagaStart);
        assert_eq!(nodes[2].label, "inner_end");
        assert_eq!(nodes[2].kind, NodeKind::SubsagaEnd);
    }
}
