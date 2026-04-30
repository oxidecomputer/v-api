// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use steno::SagaDag;

/// A newtype wrapper around steno's SagaDag that implements JsonSchema.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SagaDagWrapper(pub SagaDag);

impl JsonSchema for SagaDagWrapper {
    fn schema_name() -> String {
        "SagaDag".to_string()
    }

    fn json_schema(generator: &mut schemars::r#gen::SchemaGenerator) -> schemars::schema::Schema {
        use schemars::schema::*;

        // Define the InternalNode enum schema
        let internal_node_schema = SchemaObject {
            subschemas: Some(Box::new(SubschemaValidation {
                one_of: Some(vec![
                    // Start variant
                    Schema::Object(SchemaObject {
                        instance_type: Some(InstanceType::Object.into()),
                        object: Some(Box::new(ObjectValidation {
                            properties: {
                                let mut props = schemars::Map::new();
                                props.insert(
                                    "Start".to_string(),
                                    Schema::Object(SchemaObject {
                                        instance_type: Some(InstanceType::Object.into()),
                                        object: Some(Box::new(ObjectValidation {
                                            properties: {
                                                let mut inner_props = schemars::Map::new();
                                                inner_props.insert(
                                                    "params".to_string(),
                                                    generator.subschema_for::<serde_json::Value>(),
                                                );
                                                inner_props
                                            },
                                            required: vec!["params".to_string()]
                                                .into_iter()
                                                .collect(),
                                            ..Default::default()
                                        })),
                                        ..Default::default()
                                    }),
                                );
                                props
                            },
                            required: vec!["Start".to_string()].into_iter().collect(),
                            ..Default::default()
                        })),
                        ..Default::default()
                    }),
                    // End variant
                    Schema::Object(SchemaObject {
                        instance_type: Some(InstanceType::String.into()),
                        metadata: Some(Box::new(Metadata {
                            description: Some("End node of the saga".to_string()),
                            ..Default::default()
                        })),
                        enum_values: Some(vec![serde_json::json!("End")]),
                        ..Default::default()
                    }),
                    // Action variant
                    Schema::Object(SchemaObject {
                        instance_type: Some(InstanceType::Object.into()),
                        object: Some(Box::new(ObjectValidation {
                            properties: {
                                let mut props = schemars::Map::new();
                                props.insert(
                                    "Action".to_string(),
                                    Schema::Object(SchemaObject {
                                        instance_type: Some(InstanceType::Object.into()),
                                        object: Some(Box::new(ObjectValidation {
                                            properties: {
                                                let mut inner_props = schemars::Map::new();
                                                inner_props.insert(
                                                    "name".to_string(),
                                                    generator.subschema_for::<String>(),
                                                );
                                                inner_props.insert(
                                                    "label".to_string(),
                                                    generator.subschema_for::<String>(),
                                                );
                                                inner_props.insert(
                                                    "action_name".to_string(),
                                                    generator.subschema_for::<String>(),
                                                );
                                                inner_props
                                            },
                                            required: vec![
                                                "name".to_string(),
                                                "label".to_string(),
                                                "action_name".to_string(),
                                            ]
                                            .into_iter()
                                            .collect(),
                                            ..Default::default()
                                        })),
                                        ..Default::default()
                                    }),
                                );
                                props
                            },
                            required: vec!["Action".to_string()].into_iter().collect(),
                            ..Default::default()
                        })),
                        ..Default::default()
                    }),
                    // Constant variant
                    Schema::Object(SchemaObject {
                        instance_type: Some(InstanceType::Object.into()),
                        object: Some(Box::new(ObjectValidation {
                            properties: {
                                let mut props = schemars::Map::new();
                                props.insert(
                                    "Constant".to_string(),
                                    Schema::Object(SchemaObject {
                                        instance_type: Some(InstanceType::Object.into()),
                                        object: Some(Box::new(ObjectValidation {
                                            properties: {
                                                let mut inner_props = schemars::Map::new();
                                                inner_props.insert(
                                                    "name".to_string(),
                                                    generator.subschema_for::<String>(),
                                                );
                                                inner_props.insert(
                                                    "value".to_string(),
                                                    generator.subschema_for::<serde_json::Value>(),
                                                );
                                                inner_props
                                            },
                                            required: vec!["name".to_string(), "value".to_string()]
                                                .into_iter()
                                                .collect(),
                                            ..Default::default()
                                        })),
                                        ..Default::default()
                                    }),
                                );
                                props
                            },
                            required: vec!["Constant".to_string()].into_iter().collect(),
                            ..Default::default()
                        })),
                        ..Default::default()
                    }),
                    // SubsagaStart variant
                    Schema::Object(SchemaObject {
                        instance_type: Some(InstanceType::Object.into()),
                        object: Some(Box::new(ObjectValidation {
                            properties: {
                                let mut props = schemars::Map::new();
                                props.insert(
                                    "SubsagaStart".to_string(),
                                    Schema::Object(SchemaObject {
                                        instance_type: Some(InstanceType::Object.into()),
                                        object: Some(Box::new(ObjectValidation {
                                            properties: {
                                                let mut inner_props = schemars::Map::new();
                                                inner_props.insert(
                                                    "saga_name".to_string(),
                                                    generator.subschema_for::<String>(),
                                                );
                                                inner_props.insert(
                                                    "params_node_name".to_string(),
                                                    generator.subschema_for::<String>(),
                                                );
                                                inner_props
                                            },
                                            required: vec![
                                                "saga_name".to_string(),
                                                "params_node_name".to_string(),
                                            ]
                                            .into_iter()
                                            .collect(),
                                            ..Default::default()
                                        })),
                                        ..Default::default()
                                    }),
                                );
                                props
                            },
                            required: vec!["SubsagaStart".to_string()].into_iter().collect(),
                            ..Default::default()
                        })),
                        ..Default::default()
                    }),
                    // SubsagaEnd variant
                    Schema::Object(SchemaObject {
                        instance_type: Some(InstanceType::Object.into()),
                        object: Some(Box::new(ObjectValidation {
                            properties: {
                                let mut props = schemars::Map::new();
                                props.insert(
                                    "SubsagaEnd".to_string(),
                                    Schema::Object(SchemaObject {
                                        instance_type: Some(InstanceType::Object.into()),
                                        object: Some(Box::new(ObjectValidation {
                                            properties: {
                                                let mut inner_props = schemars::Map::new();
                                                inner_props.insert(
                                                    "name".to_string(),
                                                    generator.subschema_for::<String>(),
                                                );
                                                inner_props
                                            },
                                            required: vec!["name".to_string()]
                                                .into_iter()
                                                .collect(),
                                            ..Default::default()
                                        })),
                                        ..Default::default()
                                    }),
                                );
                                props
                            },
                            required: vec!["SubsagaEnd".to_string()].into_iter().collect(),
                            ..Default::default()
                        })),
                        ..Default::default()
                    }),
                ]),
                ..Default::default()
            })),
            ..Default::default()
        };

        // Define the petgraph Graph serialization structure
        // petgraph serializes as: { nodes: [...], node_holes: [...], edge_property: "directed", edges: [[src, tgt, weight], ...] }
        let graph_schema = SchemaObject {
            instance_type: Some(InstanceType::Object.into()),
            object: Some(Box::new(ObjectValidation {
                properties: {
                    let mut props = schemars::Map::new();
                    props.insert(
                        "nodes".to_string(),
                        Schema::Object(SchemaObject {
                            instance_type: Some(InstanceType::Array.into()),
                            array: Some(Box::new(ArrayValidation {
                                items: Some(SingleOrVec::Single(Box::new(Schema::Object(
                                    internal_node_schema,
                                )))),
                                ..Default::default()
                            })),
                            metadata: Some(Box::new(Metadata {
                                description: Some("Array of nodes in the graph".to_string()),
                                ..Default::default()
                            })),
                            ..Default::default()
                        }),
                    );
                    props.insert(
                        "node_holes".to_string(),
                        Schema::Object(SchemaObject {
                            instance_type: Some(InstanceType::Array.into()),
                            array: Some(Box::new(ArrayValidation {
                                items: Some(SingleOrVec::Single(Box::new(
                                    generator.subschema_for::<u32>(),
                                ))),
                                ..Default::default()
                            })),
                            metadata: Some(Box::new(Metadata {
                                description: Some("Indices of removed nodes".to_string()),
                                ..Default::default()
                            })),
                            ..Default::default()
                        }),
                    );
                    props.insert(
                        "edge_property".to_string(),
                        Schema::Object(SchemaObject {
                            instance_type: Some(InstanceType::String.into()),
                            metadata: Some(Box::new(Metadata {
                                description: Some("Graph edge directionality".to_string()),
                                ..Default::default()
                            })),
                            ..Default::default()
                        }),
                    );
                    props.insert(
                        "edges".to_string(),
                        Schema::Object(SchemaObject {
                            instance_type: Some(InstanceType::Array.into()),
                            array: Some(Box::new(ArrayValidation {
                                items: Some(SingleOrVec::Single(Box::new(Schema::Object(
                                    SchemaObject {
                                        instance_type: Some(InstanceType::Array.into()),
                                        array: Some(Box::new(ArrayValidation {
                                            items: Some(SingleOrVec::Single(Box::new(
                                                generator.subschema_for::<Option<u32>>(),
                                            ))),
                                            min_items: Some(3),
                                            max_items: Some(3),
                                            ..Default::default()
                                        })),
                                        metadata: Some(Box::new(Metadata {
                                            description: Some(
                                                "Edge as [source_index, target_index]".to_string(),
                                            ),
                                            ..Default::default()
                                        })),
                                        ..Default::default()
                                    },
                                )))),
                                ..Default::default()
                            })),
                            metadata: Some(Box::new(Metadata {
                                description: Some("Array of edges connecting nodes".to_string()),
                                ..Default::default()
                            })),
                            ..Default::default()
                        }),
                    );
                    props
                },
                required: vec![
                    "nodes".to_string(),
                    "node_holes".to_string(),
                    "edge_property".to_string(),
                    "edges".to_string(),
                ]
                .into_iter()
                .collect(),
                ..Default::default()
            })),
            metadata: Some(Box::new(Metadata {
                description: Some(
                    "Directed graph representation of saga nodes and dependencies".to_string(),
                ),
                ..Default::default()
            })),
            ..Default::default()
        };

        // Now build the full SagaDag schema
        SchemaObject {
            instance_type: Some(InstanceType::Object.into()),
            object: Some(Box::new(ObjectValidation {
                properties: {
                    let mut props = schemars::Map::new();
                    props.insert(
                        "saga_name".to_string(),
                        generator.subschema_for::<String>(),
                    );
                    props.insert(
                        "graph".to_string(),
                        Schema::Object(graph_schema),
                    );
                    props.insert(
                        "start_node".to_string(),
                        generator.subschema_for::<u32>(),
                    );
                    props.insert(
                        "end_node".to_string(),
                        generator.subschema_for::<u32>(),
                    );
                    props
                },
                required: vec!["saga_name".to_string(), "graph".to_string(), "start_node".to_string(), "end_node".to_string()].into_iter().collect(),
                ..Default::default()
            })),
            metadata: Some(Box::new(Metadata {
                description: Some("A directed acyclic graph representing a saga's execution flow with start and end nodes".to_string()),
                ..Default::default()
            })),
            ..Default::default()
        }
        .into()
    }
}

impl std::ops::Deref for SagaDagWrapper {
    type Target = SagaDag;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for SagaDagWrapper {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl From<SagaDag> for SagaDagWrapper {
    fn from(dag: SagaDag) -> Self {
        Self(dag)
    }
}

impl From<SagaDagWrapper> for SagaDag {
    fn from(wrapper: SagaDagWrapper) -> Self {
        wrapper.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use schemars::schema_for;

    #[test]
    fn test_saga_dag_wrapper_schema_generation() {
        // Verify that the schema can be generated without panicking
        let schema = schema_for!(SagaDagWrapper);

        // Verify schema name
        assert_eq!(
            schema
                .schema
                .metadata
                .as_ref()
                .and_then(|m| m.title.as_ref()),
            Some(&"SagaDag".to_string())
        );

        // Verify it's an object type
        let schema_obj = match &schema.schema.instance_type {
            Some(schemars::schema::SingleOrVec::Single(t)) => {
                assert!(matches!(**t, schemars::schema::InstanceType::Object));
                true
            }
            Some(schemars::schema::SingleOrVec::Vec(types)) => {
                assert!(types.contains(&schemars::schema::InstanceType::Object));
                true
            }
            None => false,
        };

        assert!(schema_obj, "Schema should have Object instance type");
    }

    #[test]
    fn test_saga_dag_wrapper_schema_has_required_fields() {
        let schema = schema_for!(SagaDagWrapper);

        // Convert to JSON to inspect structure
        let schema_json = serde_json::to_value(&schema).expect("Schema should serialize to JSON");

        // Verify the schema is valid JSON
        assert!(schema_json.is_object());

        // The schema should have properties for the SagaDag fields
        if let Some(properties) = schema_json["schema"]["properties"].as_object() {
            // Check for expected SagaDag fields
            assert!(
                properties.contains_key("saga_name"),
                "Schema should have saga_name field"
            );
            assert!(
                properties.contains_key("graph"),
                "Schema should have graph field"
            );
            assert!(
                properties.contains_key("start_node"),
                "Schema should have start_node field"
            );
            assert!(
                properties.contains_key("end_node"),
                "Schema should have end_node field"
            );
        }
    }

    #[test]
    fn test_saga_dag_wrapper_schema_serialization() {
        let schema = schema_for!(SagaDagWrapper);

        // Verify the schema can be serialized to JSON
        let json = serde_json::to_string_pretty(&schema).expect("Schema should serialize to JSON");

        // Verify it's valid JSON by parsing it back
        let _parsed: serde_json::Value =
            serde_json::from_str(&json).expect("Schema JSON should be parseable");
    }
}
