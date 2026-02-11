// Debug tools schema definitions
//
// MCP tools for JDWP debugging operations

use crate::protocol::Tool;
use serde_json::json;

pub fn get_tools() -> Vec<Tool> {
    vec![
        Tool {
            name: "debug.attach".to_string(),
            description: "Connect to a JVM via JDWP protocol".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "host": {
                        "type": "string",
                        "description": "JVM host (e.g., 'localhost')",
                        "default": "localhost"
                    },
                    "port": {
                        "type": "integer",
                        "description": "JDWP port (e.g., 5005)",
                        "default": 5005
                    },
                    "timeout_ms": {
                        "type": "integer",
                        "description": "Connection timeout in milliseconds",
                        "default": 5000
                    }
                },
                "required": ["host", "port"]
            }),
        },
        Tool {
            name: "debug.set_breakpoint".to_string(),
            description: "Set a breakpoint at a specific location".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "class_pattern": {
                        "type": "string",
                        "description": "Class name pattern (e.g., 'com.example.MyClass')"
                    },
                    "line": {
                        "type": "integer",
                        "description": "Line number (optional if method is specified — breaks at method entry)"
                    },
                    "method": {
                        "type": "string",
                        "description": "Method name (optional, helps resolve ambiguity; required when line is omitted)"
                    },
                    "condition": {
                        "type": "string",
                        "description": "Conditional expression - breakpoint only fires when this evaluates to truthy (e.g., 'count > 5', 'name.equals(\"test\")')"
                    },
                    "skip_count": {
                        "type": "integer",
                        "description": "Skip first N hits (e.g., 2 = break on 3rd hit)",
                        "default": 0
                    }
                },
                "required": ["class_pattern"]
            }),
        },
        Tool {
            name: "debug.list_breakpoints".to_string(),
            description: "List all active breakpoints".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {}
            }),
        },
        Tool {
            name: "debug.clear_breakpoint".to_string(),
            description: "Clear a specific breakpoint".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "breakpoint_id": {
                        "type": "string",
                        "description": "Breakpoint ID from list_breakpoints"
                    }
                },
                "required": ["breakpoint_id"]
            }),
        },
        Tool {
            name: "debug.continue".to_string(),
            description: "Resume execution (all threads or specific thread)".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "thread_id": {
                        "type": "string",
                        "description": "Thread ID to resume (optional, resumes all if omitted)"
                    }
                }
            }),
        },
        Tool {
            name: "debug.step_over".to_string(),
            description: "Step over current line".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "thread_id": {
                        "type": "string",
                        "description": "Thread ID to step"
                    }
                },
                "required": ["thread_id"]
            }),
        },
        Tool {
            name: "debug.step_into".to_string(),
            description: "Step into method call".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "thread_id": {
                        "type": "string",
                        "description": "Thread ID to step"
                    }
                },
                "required": ["thread_id"]
            }),
        },
        Tool {
            name: "debug.step_out".to_string(),
            description: "Step out of current method".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "thread_id": {
                        "type": "string",
                        "description": "Thread ID to step"
                    }
                },
                "required": ["thread_id"]
            }),
        },
        Tool {
            name: "debug.get_stack".to_string(),
            description: "Get stack frames with summarized variables".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "thread_id": {
                        "type": "string",
                        "description": "Thread ID"
                    },
                    "max_frames": {
                        "type": "integer",
                        "description": "Maximum number of frames to return",
                        "default": 20
                    },
                    "include_variables": {
                        "type": "boolean",
                        "description": "Include local variables in frames",
                        "default": true
                    },
                    "max_variable_depth": {
                        "type": "integer",
                        "description": "How deep to traverse object graphs (1-3)",
                        "default": 2
                    }
                },
                "required": ["thread_id"]
            }),
        },
        Tool {
            name: "debug.evaluate".to_string(),
            description: "Evaluate expression in frame context".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "thread_id": {
                        "type": "string",
                        "description": "Thread ID"
                    },
                    "frame_index": {
                        "type": "integer",
                        "description": "Stack frame index (0 = current frame)",
                        "default": 0
                    },
                    "expression": {
                        "type": "string",
                        "description": "Java expression to evaluate"
                    },
                    "max_result_length": {
                        "type": "integer",
                        "description": "Maximum length of result string",
                        "default": 500
                    },
                    "format_mode": {
                        "type": "string",
                        "enum": ["default", "elements"],
                        "default": "default",
                        "description": "'elements' enumerates array/collection items individually"
                    }
                },
                "required": ["thread_id", "expression"]
            }),
        },
        Tool {
            name: "debug.list_threads".to_string(),
            description: "List all threads with status".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {}
            }),
        },
        Tool {
            name: "debug.pause".to_string(),
            description: "Pause execution (all threads or specific thread)".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "thread_id": {
                        "type": "string",
                        "description": "Thread ID to pause (optional, pauses all if omitted)"
                    }
                }
            }),
        },
        Tool {
            name: "debug.disconnect".to_string(),
            description: "Disconnect from JVM debug session".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {}
            }),
        },
        Tool {
            name: "debug.get_last_event".to_string(),
            description: "Get the last breakpoint/event received with thread ID".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {}
            }),
        },
        Tool {
            name: "debug.set_exception_breakpoint".to_string(),
            description: "Break when an exception is thrown".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "exception_class": {
                        "type": "string",
                        "description": "Exception class name (e.g., 'java.io.IOException') or '*' for all exceptions"
                    },
                    "caught": {
                        "type": "boolean",
                        "description": "Break on caught exceptions",
                        "default": true
                    },
                    "uncaught": {
                        "type": "boolean",
                        "description": "Break on uncaught exceptions",
                        "default": true
                    },
                    "package_filter": {
                        "type": "string",
                        "description": "Only break when throw location is in this package (e.g., 'com.myapp')"
                    }
                },
                "required": ["exception_class"]
            }),
        },
        Tool {
            name: "debug.add_watch".to_string(),
            description: "Add a watch expression to evaluate on each step or breakpoint".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "expression": {
                        "type": "string",
                        "description": "Expression to watch (e.g., 'myVar.size()')"
                    },
                    "evaluate_on": {
                        "type": "string",
                        "enum": ["steps", "breakpoints_only"],
                        "default": "steps",
                        "description": "'steps' evaluates on every step, 'breakpoints_only' only at breakpoint hits"
                    }
                },
                "required": ["expression"]
            }),
        },
        Tool {
            name: "debug.remove_watch".to_string(),
            description: "Remove a watch expression".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "expression": {
                        "type": "string",
                        "description": "Expression to remove from watches"
                    }
                },
                "required": ["expression"]
            }),
        },
        Tool {
            name: "debug.list_watches".to_string(),
            description: "List all watch expressions".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {}
            }),
        },
        Tool {
            name: "debug.set_value".to_string(),
            description: "Modify a local variable value in the current frame".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "thread_id": {
                        "type": "string",
                        "description": "Thread ID"
                    },
                    "frame_index": {
                        "type": "integer",
                        "description": "Stack frame index (0 = current frame)",
                        "default": 0
                    },
                    "variable_name": {
                        "type": "string",
                        "description": "Name of the variable to modify"
                    },
                    "value": {
                        "type": "string",
                        "description": "New value — strings quoted: '\"hello\"', ints: '42', bools: 'true'"
                    }
                },
                "required": ["thread_id", "variable_name", "value"]
            }),
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_tools_returns_19_tools() {
        let tools = get_tools();
        assert_eq!(tools.len(), 19);
    }

    #[test]
    fn set_breakpoint_has_skip_count_and_required_class_pattern() {
        let tools = get_tools();
        let bp = tools.iter().find(|t| t.name == "debug.set_breakpoint").unwrap();
        let schema = &bp.input_schema;
        assert!(schema["properties"]["skip_count"].is_object());
        let required = schema["required"].as_array().unwrap();
        let required_strs: Vec<&str> = required.iter().map(|v| v.as_str().unwrap()).collect();
        assert!(required_strs.contains(&"class_pattern"));
        assert!(!required_strs.contains(&"line"));
    }

    #[test]
    fn set_exception_breakpoint_has_package_filter() {
        let tools = get_tools();
        let t = tools.iter().find(|t| t.name == "debug.set_exception_breakpoint").unwrap();
        assert!(t.input_schema["properties"]["package_filter"].is_object());
    }

    #[test]
    fn evaluate_has_format_mode_enum() {
        let tools = get_tools();
        let t = tools.iter().find(|t| t.name == "debug.evaluate").unwrap();
        let fm = &t.input_schema["properties"]["format_mode"];
        let enum_vals: Vec<&str> = fm["enum"].as_array().unwrap()
            .iter().map(|v| v.as_str().unwrap()).collect();
        assert_eq!(enum_vals, vec!["default", "elements"]);
    }

    #[test]
    fn add_watch_has_evaluate_on_enum() {
        let tools = get_tools();
        let t = tools.iter().find(|t| t.name == "debug.add_watch").unwrap();
        let eo = &t.input_schema["properties"]["evaluate_on"];
        let enum_vals: Vec<&str> = eo["enum"].as_array().unwrap()
            .iter().map(|v| v.as_str().unwrap()).collect();
        assert_eq!(enum_vals, vec!["steps", "breakpoints_only"]);
    }

    #[test]
    fn set_value_exists_with_required_fields() {
        let tools = get_tools();
        let t = tools.iter().find(|t| t.name == "debug.set_value").unwrap();
        let required = t.input_schema["required"].as_array().unwrap();
        let required_strs: Vec<&str> = required.iter().map(|v| v.as_str().unwrap()).collect();
        assert!(required_strs.contains(&"thread_id"));
        assert!(required_strs.contains(&"variable_name"));
        assert!(required_strs.contains(&"value"));
    }

    #[test]
    fn all_tool_names_are_unique() {
        let tools = get_tools();
        let mut names: Vec<&str> = tools.iter().map(|t| t.name.as_str()).collect();
        names.sort();
        names.dedup();
        assert_eq!(names.len(), tools.len());
    }
}
