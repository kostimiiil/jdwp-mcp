// MCP request handlers
//
// Handles initialize, list tools, and debug tool execution

use crate::protocol::*;
use crate::session::{DebugSession, SessionManager};
use crate::tools;
use serde_json::json;
use tracing::{debug, info, warn};

pub struct RequestHandler {
    session_manager: SessionManager,
}

impl RequestHandler {
    pub fn new() -> Self {
        Self {
            session_manager: SessionManager::new(),
        }
    }

    pub async fn handle_request(&self, request: JsonRpcRequest) -> JsonRpcResponse {
        let result = match request.method.as_str() {
            "initialize" => self.handle_initialize(request.params),
            "tools/list" => self.handle_list_tools(),
            "tools/call" => self.handle_call_tool(request.params).await,
            _ => Err(JsonRpcError {
                code: METHOD_NOT_FOUND,
                message: format!("Method not found: {}", request.method),
                data: None,
            }),
        };

        match result {
            Ok(value) => JsonRpcResponse {
                jsonrpc: "2.0".to_string(),
                id: request.id,
                result: Some(value),
                error: None,
            },
            Err(error) => JsonRpcResponse {
                jsonrpc: "2.0".to_string(),
                id: request.id,
                result: None,
                error: Some(error),
            },
        }
    }

    pub async fn handle_notification(&self, notification: JsonRpcNotification) {
        match notification.method.as_str() {
            "notifications/initialized" => {
                info!("Client initialized");
            }
            "notifications/cancelled" => {
                debug!("Request cancelled");
            }
            _ => {
                warn!("Unknown notification: {}", notification.method);
            }
        }
    }

    fn handle_initialize(&self, params: Option<serde_json::Value>) -> Result<serde_json::Value, JsonRpcError> {
        let _params: InitializeParams = serde_json::from_value(params.unwrap_or(json!({})))
            .map_err(|e| JsonRpcError {
                code: INVALID_PARAMS,
                message: format!("Invalid initialize params: {}", e),
                data: None,
            })?;

        let result = InitializeResult {
            protocol_version: "2024-11-05".to_string(),
            capabilities: ServerCapabilities {
                tools: ToolsCapability {},
            },
            server_info: ServerInfo {
                name: "jdwp-mcp".to_string(),
                version: env!("CARGO_PKG_VERSION").to_string(),
            },
            instructions: Some(
                "JDWP debugging server for Java applications. \
                Start by using debug.attach to connect to a JVM, \
                then use debug.set_breakpoint, debug.get_stack, etc."
                    .to_string(),
            ),
        };

        Ok(serde_json::to_value(result).unwrap())
    }

    fn handle_list_tools(&self) -> Result<serde_json::Value, JsonRpcError> {
        let result = ListToolsResult {
            tools: tools::get_tools(),
        };

        Ok(serde_json::to_value(result).unwrap())
    }

    async fn handle_call_tool(&self, params: Option<serde_json::Value>) -> Result<serde_json::Value, JsonRpcError> {
        let call_params: CallToolParams = serde_json::from_value(params.unwrap_or(json!({})))
            .map_err(|e| JsonRpcError {
                code: INVALID_PARAMS,
                message: format!("Invalid tool call params: {}", e),
                data: None,
            })?;

        // Route to appropriate handler based on tool name
        let result = match call_params.name.as_str() {
            "debug.attach" => self.handle_attach(call_params.arguments).await,
            "debug.set_breakpoint" => self.handle_set_breakpoint(call_params.arguments).await,
            "debug.list_breakpoints" => self.handle_list_breakpoints(call_params.arguments).await,
            "debug.clear_breakpoint" => self.handle_clear_breakpoint(call_params.arguments).await,
            "debug.continue" => self.handle_continue(call_params.arguments).await,
            "debug.step_over" => self.handle_step_over(call_params.arguments).await,
            "debug.step_into" => self.handle_step_into(call_params.arguments).await,
            "debug.step_out" => self.handle_step_out(call_params.arguments).await,
            "debug.get_stack" => self.handle_get_stack(call_params.arguments).await,
            "debug.evaluate" => self.handle_evaluate(call_params.arguments).await,
            "debug.list_threads" => self.handle_list_threads(call_params.arguments).await,
            "debug.pause" => self.handle_pause(call_params.arguments).await,
            "debug.disconnect" => self.handle_disconnect(call_params.arguments).await,
            "debug.get_last_event" => self.handle_get_last_event(call_params.arguments).await,
            "debug.set_exception_breakpoint" => self.handle_set_exception_breakpoint(call_params.arguments).await,
            "debug.add_watch" => self.handle_add_watch(call_params.arguments).await,
            "debug.remove_watch" => self.handle_remove_watch(call_params.arguments).await,
            "debug.list_watches" => self.handle_list_watches(call_params.arguments).await,
            "debug.set_value" => self.handle_set_value(call_params.arguments).await,
            _ => Err(format!("Unknown tool: {}", call_params.name)),
        };

        match result {
            Ok(content) => {
                let call_result = CallToolResult {
                    content: vec![ContentBlock::Text { text: content }],
                    is_error: None,
                };
                Ok(serde_json::to_value(call_result).unwrap())
            }
            Err(error) => {
                let call_result = CallToolResult {
                    content: vec![ContentBlock::Text { text: error.clone() }],
                    is_error: Some(true),
                };
                Ok(serde_json::to_value(call_result).unwrap())
            }
        }
    }

    // Tool implementations (stubs for now)
    async fn handle_attach(&self, args: serde_json::Value) -> Result<String, String> {
        let host = args.get("host").and_then(|v| v.as_str()).unwrap_or("localhost");
        let port = args.get("port").and_then(|v| v.as_u64()).unwrap_or(5005) as u16;

        match jdwp_client::JdwpConnection::connect(host, port).await {
            Ok(connection) => {
                // Create session
                let session_id = self.session_manager.create_session(connection).await;

                // Get session guard once to prevent race between spawn and store
                let session_guard = self.session_manager.get_current_session().await
                    .ok_or_else(|| "Failed to get session after creation".to_string())?;

                // Clone connection, spawn task, and store handle in single critical section
                {
                    let mut session = session_guard.lock().await;
                    let connection_clone = session.connection.clone();

                    // Spawn event listener task
                    let session_manager = self.session_manager.clone();
                    let task_handle = tokio::spawn(async move {
                        loop {
                            // Receive event without holding any locks!
                            let event_opt = connection_clone.recv_event().await;

                            // Store event (brief lock acquisition)
                            if let Some(event_set) = event_opt {
                                if let Some(session_guard) = session_manager.get_current_session().await {
                                    let mut session = session_guard.lock().await;
                                    // Route step events to the step channel if present
                                    let is_step = event_set.events.iter().any(|e|
                                        matches!(e.details, jdwp_client::events::EventKind::Step { .. })
                                    );
                                    if is_step {
                                        if let Some(tx) = &session.step_event_tx {
                                            let _ = tx.try_send(event_set.clone());
                                        }
                                    }

                                    // Check conditional breakpoints and hit counts
                                    let is_breakpoint = event_set.events.iter().any(|e|
                                        matches!(e.details, jdwp_client::events::EventKind::Breakpoint { .. })
                                    );
                                    if is_breakpoint {
                                        let mut should_resume = false;
                                        for event in &event_set.events {
                                            if let jdwp_client::events::EventKind::Breakpoint { thread, .. } = &event.details {
                                                // Extract bp info (immutable borrow)
                                                let bp_info = session.breakpoints.values()
                                                    .find(|bp| bp.request_id == event.request_id)
                                                    .map(|bp| (bp.condition.clone(), bp.skip_count));

                                                // Increment hit count and check skip (mutable borrow)
                                                let mut skip_due_to_count = false;
                                                if let Some(bp) = session.breakpoints.values_mut()
                                                    .find(|bp| bp.request_id == event.request_id) {
                                                    bp.hit_count += 1;
                                                    if bp.hit_count <= bp.skip_count {
                                                        skip_due_to_count = true;
                                                    }
                                                }

                                                if skip_due_to_count {
                                                    should_resume = true;
                                                } else if let Some((Some(cond_expr), _)) = &bp_info {
                                                    // Evaluate condition
                                                    match evaluate_expression(&mut session, *thread, 0, cond_expr).await {
                                                        Ok(val) => {
                                                            if !is_truthy(&mut session, &val).await {
                                                                should_resume = true;
                                                            }
                                                        }
                                                        Err(_) => {
                                                            should_resume = true;
                                                        }
                                                    }
                                                }
                                            }
                                        }

                                        if should_resume {
                                            let _ = session.connection.resume_all().await;
                                            continue; // Don't store as last_event
                                        }

                                        // Evaluate breakpoints_only watches
                                        let bp_watches: Vec<String> = session.watch_expressions.iter()
                                            .filter(|w| w.evaluate_on == crate::session::WatchMode::BreakpointsOnly)
                                            .map(|w| w.expression.clone())
                                            .collect();
                                        if !bp_watches.is_empty() {
                                            if let Some(thread_id) = event_set.events.iter().find_map(|e| {
                                                if let jdwp_client::events::EventKind::Breakpoint { thread, .. } = &e.details {
                                                    Some(*thread)
                                                } else { None }
                                            }) {
                                                let mut results = Vec::new();
                                                for expr in &bp_watches {
                                                    let val_str = match evaluate_expression(&mut session, thread_id, 0, expr).await {
                                                        Ok(val) => format_value_deep_with_thread(&mut session, &val, 200, thread_id).await,
                                                        Err(e) => format!("<error: {}>", e),
                                                    };
                                                    results.push((expr.clone(), val_str));
                                                }
                                                session.last_watch_results = Some(results);
                                            }
                                        } else {
                                            session.last_watch_results = None;
                                        }
                                    }

                                    // Check exception breakpoints with package filter
                                    let is_exception = event_set.events.iter().any(|e|
                                        matches!(e.details, jdwp_client::events::EventKind::Exception { .. })
                                    );
                                    if is_exception {
                                        let mut should_resume = false;
                                        for event in &event_set.events {
                                            if let jdwp_client::events::EventKind::Exception { location, .. } = &event.details {
                                                // Extract package_filter (immutable borrow)
                                                let package_filter = session.breakpoints.values()
                                                    .find(|bp| bp.request_id == event.request_id)
                                                    .and_then(|bp| bp.package_filter.clone());

                                                // Increment hit count (mutable borrow)
                                                if let Some(bp) = session.breakpoints.values_mut()
                                                    .find(|bp| bp.request_id == event.request_id) {
                                                    bp.hit_count += 1;
                                                }

                                                // Check package filter
                                                if let Some(filter) = package_filter {
                                                    if let Ok(sig) = session.connection.get_signature(location.class_id).await {
                                                        let class_name = jvm_signature_to_class_name(&sig);
                                                        if !class_name.starts_with(&filter) {
                                                            should_resume = true;
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                        if should_resume {
                                            let _ = session.connection.resume_all().await;
                                            continue; // Don't store as last_event
                                        }
                                    }

                                    session.last_event = Some(event_set);
                                } else {
                                    break; // Session gone
                                }
                            } else {
                                break; // Connection closed
                            }
                        }
                        info!("Event listener task stopped");
                    });

                    // Store task handle before releasing lock - prevents race with disconnect
                    session.event_listener_task = Some(task_handle);
                }

                Ok(format!("Connected to JVM at {}:{} (session: {})", host, port, session_id))
            }
            Err(e) => Err(format!("Failed to connect: {}", e)),
        }
    }

    async fn handle_set_breakpoint(&self, args: serde_json::Value) -> Result<String, String> {
        let class_pattern = args.get("class_pattern")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "Missing 'class_pattern' parameter".to_string())?;

        let line = args.get("line")
            .and_then(|v| v.as_i64())
            .map(|v| v as i32);

        let method_hint = args.get("method").and_then(|v| v.as_str());

        let skip_count = args.get("skip_count")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u32;

        // Must have either line or method
        if line.is_none() && method_hint.is_none() {
            return Err("Either 'line' or 'method' parameter is required".to_string());
        }

        // Get current session
        let session_guard = self.session_manager.get_current_session().await
            .ok_or_else(|| "No active debug session. Use debug.attach first.".to_string())?;

        let mut session = session_guard.lock().await;

        // Convert class name to JVM signature format
        let signature = if class_pattern.starts_with('L') && class_pattern.ends_with(';') {
            class_pattern.to_string()
        } else {
            format!("L{};", class_pattern.replace('.', "/"))
        };

        // Find the class
        let classes = session.connection.classes_by_signature(&signature).await
            .map_err(|e| format!("Failed to find class: {}", e))?;

        if classes.is_empty() {
            return Err(format!("Class not found: {}", class_pattern));
        }

        let class = &classes[0];

        // Get methods
        let methods = session.connection.get_methods(class.type_id).await
            .map_err(|e| format!("Failed to get methods: {}", e))?;

        // Determine breakpoint target based on whether line is provided
        let (target_method_name, bp_line, bytecode_index) = if let Some(line) = line {
            // Line-based breakpoint (original behavior)
            let mut target_method = None;

            for method in &methods {
                if let Some(hint) = method_hint {
                    if method.name == hint {
                        target_method = Some(method);
                        break;
                    }
                }

                if let Ok(line_table) = session.connection.get_line_table(class.type_id, method.method_id).await {
                    if line_table.lines.iter().any(|e| e.line_number == line) {
                        target_method = Some(method);
                        break;
                    }
                }
            }

            let method = target_method.ok_or_else(|| {
                format!("No method found containing line {} in class {}", line, class_pattern)
            })?;

            let line_table = session.connection.get_line_table(class.type_id, method.method_id).await
                .map_err(|e| format!("Failed to get line table: {}", e))?;

            let line_entry = line_table.lines.iter()
                .find(|e| e.line_number == line)
                .ok_or_else(|| format!("Line {} not found in method {}", line, method.name))?;

            (method.name.clone(), line as u32, line_entry.line_code_index)
        } else {
            // Method entry breakpoint — find method and use its first line
            let method_name = method_hint.unwrap(); // guaranteed by check above
            let method = methods.iter()
                .find(|m| m.name == method_name)
                .ok_or_else(|| format!("Method '{}' not found in class {}", method_name, class_pattern))?;

            let line_table = session.connection.get_line_table(class.type_id, method.method_id).await
                .map_err(|e| format!("Failed to get line table for method '{}': {}", method_name, e))?;

            let first_entry = line_table.lines.first()
                .ok_or_else(|| format!("Method '{}' has no line table (possibly native)", method_name))?;

            (method.name.clone(), first_entry.line_number as u32, first_entry.line_code_index)
        };

        // Find method ID for the resolved method
        let method = methods.iter()
            .find(|m| m.name == target_method_name)
            .ok_or_else(|| "Internal error: method not found after resolution".to_string())?;

        // Set the breakpoint
        let request_id = session.connection.set_breakpoint(
            class.type_id,
            method.method_id,
            bytecode_index,
            jdwp_client::SuspendPolicy::All,
        ).await.map_err(|e| format!("Failed to set breakpoint: {}", e))?;

        let condition = args.get("condition")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        // Track the breakpoint in session
        let bp_id = format!("bp_{}", request_id);
        session.breakpoints.insert(bp_id.clone(), crate::session::BreakpointInfo {
            id: bp_id.clone(),
            request_id,
            class_pattern: class_pattern.to_string(),
            line: bp_line,
            method: Some(target_method_name.clone()),
            enabled: true,
            hit_count: 0,
            exception_class: None,
            condition,
            skip_count,
            package_filter: None,
        });

        let skip_info = if skip_count > 0 {
            format!("\n   Skip count: {} (breaks on hit #{})", skip_count, skip_count + 1)
        } else {
            String::new()
        };

        Ok(format!(
            "Breakpoint set at {}:{}\n   Method: {}\n   Breakpoint ID: {}\n   JDWP Request ID: {}{}",
            class_pattern, bp_line, target_method_name, bp_id, request_id, skip_info
        ))
    }

    async fn handle_list_breakpoints(&self, _args: serde_json::Value) -> Result<String, String> {
        let session_guard = self.session_manager.get_current_session().await
            .ok_or_else(|| "No active debug session".to_string())?;

        let session = session_guard.lock().await;

        if session.breakpoints.is_empty() {
            return Ok("No breakpoints set".to_string());
        }

        let mut output = format!("📍 {} breakpoint(s):\n\n", session.breakpoints.len());

        for (_, bp) in session.breakpoints.iter() {
            if let Some(exc_class) = &bp.exception_class {
                output.push_str(&format!(
                    "  {} [{}] Exception: {}\n",
                    if bp.enabled { "✓" } else { "✗" },
                    bp.id,
                    exc_class
                ));
            } else {
                output.push_str(&format!(
                    "  {} [{}] {}:{}\n",
                    if bp.enabled { "✓" } else { "✗" },
                    bp.id,
                    bp.class_pattern,
                    bp.line
                ));
                if let Some(method) = &bp.method {
                    output.push_str(&format!("     Method: {}\n", method));
                }
            }
            if let Some(condition) = &bp.condition {
                output.push_str(&format!("     Condition: {}\n", condition));
            }
            if bp.hit_count > 0 {
                output.push_str(&format!("     Hits: {}\n", bp.hit_count));
            }
        }

        Ok(output)
    }

    async fn handle_clear_breakpoint(&self, args: serde_json::Value) -> Result<String, String> {
        let bp_id = args.get("breakpoint_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "Missing 'breakpoint_id' parameter".to_string())?;

        let session_guard = self.session_manager.get_current_session().await
            .ok_or_else(|| "No active debug session".to_string())?;

        let mut session = session_guard.lock().await;

        // Find the breakpoint
        let bp_info = session.breakpoints.get(bp_id)
            .ok_or_else(|| format!("Breakpoint not found: {}", bp_id))?
            .clone();

        // Clear the breakpoint in the JVM (use correct event kind)
        let event_kind = if bp_info.exception_class.is_some() {
            jdwp_client::commands::event_kinds::EXCEPTION
        } else {
            jdwp_client::commands::event_kinds::BREAKPOINT
        };
        session.connection.clear_event_request(event_kind, bp_info.request_id).await
            .map_err(|e| format!("Failed to clear breakpoint: {}", e))?;

        // Remove from session
        session.breakpoints.remove(bp_id);

        Ok(format!(
            "✅ Breakpoint cleared: {} at {}:{}\n   JDWP Request ID: {}",
            bp_id, bp_info.class_pattern, bp_info.line, bp_info.request_id
        ))
    }

    async fn handle_continue(&self, _args: serde_json::Value) -> Result<String, String> {
        let session_guard = self.session_manager.get_current_session().await
            .ok_or_else(|| "No active debug session".to_string())?;

        let mut session = session_guard.lock().await;

        session.connection.resume_all().await
            .map_err(|e| format!("Failed to resume: {}", e))?;

        Ok("▶️  Execution resumed".to_string())
    }

    async fn handle_step_over(&self, args: serde_json::Value) -> Result<String, String> {
        self.execute_step(args, jdwp_client::commands::step_depths::OVER).await
    }

    async fn handle_step_into(&self, args: serde_json::Value) -> Result<String, String> {
        self.execute_step(args, jdwp_client::commands::step_depths::INTO).await
    }

    async fn handle_step_out(&self, args: serde_json::Value) -> Result<String, String> {
        self.execute_step(args, jdwp_client::commands::step_depths::OUT).await
    }

    async fn execute_step(&self, args: serde_json::Value, step_depth: i32) -> Result<String, String> {
        let thread_id = parse_thread_id(&args)?;

        let session_guard = self.session_manager.get_current_session().await
            .ok_or_else(|| "No active debug session".to_string())?;

        // Create channel for step event
        let (tx, mut rx) = tokio::sync::mpsc::channel::<jdwp_client::EventSet>(1);

        // Set up step request
        let request_id = {
            let mut session = session_guard.lock().await;
            session.step_event_tx = Some(tx);
            session.connection.set_step_request(
                thread_id,
                jdwp_client::commands::step_sizes::LINE,
                step_depth,
                jdwp_client::SuspendPolicy::All,
            ).await.map_err(|e| format!("Failed to set step request: {}", e))?
        };

        // Resume execution
        {
            let mut session = session_guard.lock().await;
            session.connection.resume_all().await
                .map_err(|e| format!("Failed to resume: {}", e))?;
        }

        // Wait for step event with timeout
        let step_result = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            rx.recv(),
        ).await;

        // Clean up: remove channel and clear step request
        {
            let mut session = session_guard.lock().await;
            session.step_event_tx = None;
            let _ = session.connection.clear_event_request(
                jdwp_client::commands::event_kinds::SINGLE_STEP,
                request_id,
            ).await;
        }

        // Process result
        match step_result {
            Ok(Some(event_set)) => {
                for event in &event_set.events {
                    if let jdwp_client::events::EventKind::Step { thread, location } = &event.details {
                        let mut session = session_guard.lock().await;
                        let (class_name, method_name, line) = resolve_location(&mut session, location).await;
                        let depth_name = match step_depth {
                            0 => "into",
                            1 => "over",
                            2 => "out",
                            _ => "step",
                        };
                        let thread_info = format_thread_info(&mut session, *thread).await;
                        let mut output = format!(
                            "Stepped {} to {}::{}() line {}\n  {}",
                            depth_name, class_name, method_name, line, thread_info
                        );

                        // Evaluate watch expressions (steps mode only)
                        let step_watches: Vec<String> = session.watch_expressions.iter()
                            .filter(|w| w.evaluate_on == crate::session::WatchMode::Steps)
                            .map(|w| w.expression.clone())
                            .collect();
                        if !step_watches.is_empty() {
                            output.push_str("\n\n  Watch expressions:");
                            for expr in &step_watches {
                                let watch_result = match evaluate_expression(&mut session, *thread, 0, expr).await {
                                    Ok(val) => format_value_deep_with_thread(&mut session, &val, 200, *thread).await,
                                    Err(e) => format!("<error: {}>", e),
                                };
                                output.push_str(&format!("\n    {} = {}", expr, watch_result));
                            }
                        }

                        return Ok(output);
                    }
                }
                Ok("Step completed (no location info)".to_string())
            }
            Ok(None) => Err("Step event channel closed unexpectedly".to_string()),
            Err(_) => Err("Step timed out after 10 seconds".to_string()),
        }
    }

    async fn handle_get_stack(&self, args: serde_json::Value) -> Result<String, String> {
        let session_guard = self.session_manager.get_current_session().await
            .ok_or_else(|| "No active debug session".to_string())?;

        let mut session = session_guard.lock().await;

        let thread_id = args.get("thread_id")
            .and_then(|v| v.as_str())
            .and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok());

        let max_frames = args.get("max_frames")
            .and_then(|v| v.as_i64())
            .unwrap_or(20) as usize;

        let include_variables = args.get("include_variables")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);

        // If no thread specified, get all threads and use the first suspended one
        let target_thread = if let Some(tid) = thread_id {
            tid
        } else {
            let threads = session.connection.get_all_threads().await
                .map_err(|e| format!("Failed to get threads: {}", e))?;

            *threads.first().ok_or_else(|| "No threads found".to_string())?
        };

        // Get frames (-1 means all frames to avoid INVALID_LENGTH errors)
        let mut frames = session.connection.get_frames(target_thread, 0, -1).await
            .map_err(|e| format!("Failed to get frames: {}", e))?;

        // Truncate to max_frames
        frames.truncate(max_frames);

        if frames.is_empty() {
            return Ok(format!("Thread {:x} has no stack frames", target_thread));
        }

        let mut output = format!("🔍 Stack for thread {:x} ({} frames):\n\n", target_thread, frames.len());

        for (idx, frame) in frames.iter().enumerate() {
            let (class_name, method_name, line) = resolve_location(&mut session, &frame.location).await;
            output.push_str(&format!("Frame {}:\n", idx));
            output.push_str(&format!("  Location: {}::{}() line {}\n", class_name, method_name, line));

            // Get variables if requested
            if include_variables {
                match session.connection.get_variable_table(frame.location.class_id, frame.location.method_id).await {
                    Ok(var_table) => {
                        let current_index = frame.location.index;
                        let active_vars: Vec<_> = var_table.iter()
                            .filter(|v| current_index >= v.code_index && current_index < v.code_index + v.length as u64)
                            .collect();

                        if !active_vars.is_empty() {
                            output.push_str(&format!("  Variables ({}):\n", active_vars.len()));

                            let slots: Vec<jdwp_client::stackframe::VariableSlot> = active_vars.iter()
                                .map(|v| jdwp_client::stackframe::VariableSlot {
                                    slot: v.slot as i32,
                                    sig_byte: v.signature.as_bytes()[0],
                                })
                                .collect();

                            if let Ok(values) = session.connection.get_frame_values(target_thread, frame.frame_id, slots).await {
                                for (var, value) in active_vars.iter().zip(values.iter()) {
                                    let formatted_value = format_value_deep_with_thread(
                                        &mut session, value, 200, target_thread,
                                    ).await;
                                    output.push_str(&format!("    {} = {}\n", var.name, formatted_value));
                                }
                            }
                        }
                    }
                    Err(_) => {}
                }
            }

            output.push_str("\n");
        }

        Ok(output)
    }

    async fn handle_evaluate(&self, args: serde_json::Value) -> Result<String, String> {
        let thread_id = parse_thread_id(&args)?;
        let frame_index = args.get("frame_index")
            .and_then(|v| v.as_i64())
            .unwrap_or(0) as i32;
        let expression = args.get("expression")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "Missing 'expression' parameter".to_string())?
            .to_string();
        let max_result_length = args.get("max_result_length")
            .and_then(|v| v.as_u64())
            .unwrap_or(1000) as usize;
        let format_mode = args.get("format_mode")
            .and_then(|v| v.as_str())
            .unwrap_or("default");

        let session_guard = self.session_manager.get_current_session().await
            .ok_or_else(|| "No active debug session".to_string())?;

        let mut session = session_guard.lock().await;

        let result = evaluate_expression(&mut session, thread_id, frame_index, &expression).await?;

        if format_mode == "elements" {
            let formatted = format_collection_elements(&mut session, &result, thread_id, 50, 200).await;
            Ok(formatted)
        } else {
            let formatted = format_value_deep(&mut session, &result, max_result_length).await;
            Ok(formatted)
        }
    }

    async fn handle_list_threads(&self, _args: serde_json::Value) -> Result<String, String> {
        let session_guard = self.session_manager.get_current_session().await
            .ok_or_else(|| "No active debug session".to_string())?;

        let mut session = session_guard.lock().await;

        let threads = session.connection.get_all_threads().await
            .map_err(|e| format!("Failed to get threads: {}", e))?;

        let mut output = format!("🧵 {} thread(s):\n\n", threads.len());

        for (idx, thread_id) in threads.iter().enumerate() {
            // Get thread name
            let name = session.connection.get_thread_name(*thread_id).await
                .unwrap_or_else(|_| "???".to_string());

            output.push_str(&format!("  Thread {} \"{}\" (ID: 0x{:x})\n", idx + 1, name, thread_id));

            // Try to get frame count
            match session.connection.get_frames(*thread_id, 0, 1).await {
                Ok(frames) if !frames.is_empty() => {
                    output.push_str("     Status: Has frames (possibly suspended)\n");
                }
                Ok(_) => {
                    output.push_str("     Status: Running (no frames)\n");
                }
                Err(_) => {
                    output.push_str("     Status: Cannot inspect\n");
                }
            }
        }

        Ok(output)
    }

    async fn handle_pause(&self, _args: serde_json::Value) -> Result<String, String> {
        let session_guard = self.session_manager.get_current_session().await
            .ok_or_else(|| "No active debug session".to_string())?;

        let mut session = session_guard.lock().await;

        session.connection.suspend_all().await
            .map_err(|e| format!("Failed to suspend: {}", e))?;

        Ok("⏸️  Execution paused (all threads suspended)".to_string())
    }

    async fn handle_disconnect(&self, _args: serde_json::Value) -> Result<String, String> {
        let current_session_id = self.session_manager.get_current_session_id().await;

        if let Some(session_id) = current_session_id {
            // Remove the session (this will also clear current session)
            self.session_manager.remove_session(&session_id).await;
            Ok(format!("✅ Disconnected from debug session: {}", session_id))
        } else {
            Err("No active debug session to disconnect".to_string())
        }
    }

    async fn handle_set_exception_breakpoint(&self, args: serde_json::Value) -> Result<String, String> {
        let exception_class = args.get("exception_class")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "Missing 'exception_class' parameter".to_string())?;

        let caught = args.get("caught").and_then(|v| v.as_bool()).unwrap_or(true);
        let uncaught = args.get("uncaught").and_then(|v| v.as_bool()).unwrap_or(true);

        let session_guard = self.session_manager.get_current_session().await
            .ok_or_else(|| "No active debug session. Use debug.attach first.".to_string())?;

        let mut session = session_guard.lock().await;

        let class_id: u64 = if exception_class == "*" {
            0
        } else {
            let signature = if exception_class.starts_with('L') && exception_class.ends_with(';') {
                exception_class.to_string()
            } else {
                format!("L{};", exception_class.replace('.', "/"))
            };

            let classes = session.connection.classes_by_signature(&signature).await
                .map_err(|e| format!("Failed to find exception class: {}", e))?;

            if classes.is_empty() {
                return Err(format!("Exception class not found: {}", exception_class));
            }

            classes[0].type_id
        };

        let package_filter = args.get("package_filter")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let request_id = session.connection.set_exception_breakpoint(
            class_id,
            caught,
            uncaught,
            jdwp_client::SuspendPolicy::All,
        ).await.map_err(|e| format!("Failed to set exception breakpoint: {}", e))?;

        let bp_id = format!("exc_{}", request_id);
        session.breakpoints.insert(bp_id.clone(), crate::session::BreakpointInfo {
            id: bp_id.clone(),
            request_id,
            class_pattern: exception_class.to_string(),
            line: 0,
            method: None,
            enabled: true,
            hit_count: 0,
            exception_class: Some(exception_class.to_string()),
            condition: None,
            skip_count: 0,
            package_filter: package_filter.clone(),
        });

        let class_display = if exception_class == "*" { "all exceptions" } else { exception_class };
        let filter_info = package_filter.as_deref()
            .map(|f| format!("\n  Package filter: {}", f))
            .unwrap_or_default();
        Ok(format!(
            "Exception breakpoint set for {}\n  Caught: {}\n  Uncaught: {}\n  Breakpoint ID: {}\n  JDWP Request ID: {}{}",
            class_display, caught, uncaught, bp_id, request_id, filter_info
        ))
    }

    async fn handle_add_watch(&self, args: serde_json::Value) -> Result<String, String> {
        let expression = args.get("expression")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "Missing 'expression' parameter".to_string())?
            .to_string();

        let evaluate_on = match args.get("evaluate_on").and_then(|v| v.as_str()) {
            Some("breakpoints_only") => crate::session::WatchMode::BreakpointsOnly,
            _ => crate::session::WatchMode::Steps,
        };

        let session_guard = self.session_manager.get_current_session().await
            .ok_or_else(|| "No active debug session".to_string())?;

        let mut session = session_guard.lock().await;

        if session.watch_expressions.iter().any(|w| w.expression == expression) {
            return Ok(format!("Watch expression already exists: {}", expression));
        }

        let mode_str = match &evaluate_on {
            crate::session::WatchMode::Steps => "steps",
            crate::session::WatchMode::BreakpointsOnly => "breakpoints_only",
        };
        session.watch_expressions.push(crate::session::WatchExpression {
            expression: expression.clone(),
            evaluate_on,
        });
        Ok(format!("Watch added: {} (evaluate_on: {})\n  Total watches: {}", expression, mode_str, session.watch_expressions.len()))
    }

    async fn handle_remove_watch(&self, args: serde_json::Value) -> Result<String, String> {
        let expression = args.get("expression")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "Missing 'expression' parameter".to_string())?
            .to_string();

        let session_guard = self.session_manager.get_current_session().await
            .ok_or_else(|| "No active debug session".to_string())?;

        let mut session = session_guard.lock().await;

        if let Some(pos) = session.watch_expressions.iter().position(|w| w.expression == expression) {
            session.watch_expressions.remove(pos);
            Ok(format!("Watch removed: {}\n  Remaining watches: {}", expression, session.watch_expressions.len()))
        } else {
            Err(format!("Watch expression not found: {}", expression))
        }
    }

    async fn handle_list_watches(&self, _args: serde_json::Value) -> Result<String, String> {
        let session_guard = self.session_manager.get_current_session().await
            .ok_or_else(|| "No active debug session".to_string())?;

        let session = session_guard.lock().await;

        if session.watch_expressions.is_empty() {
            return Ok("No watch expressions set".to_string());
        }

        let mut output = format!("{} watch expression(s):\n\n", session.watch_expressions.len());
        for (idx, watch) in session.watch_expressions.iter().enumerate() {
            let mode_str = match &watch.evaluate_on {
                crate::session::WatchMode::Steps => "steps",
                crate::session::WatchMode::BreakpointsOnly => "breakpoints_only",
            };
            output.push_str(&format!("  {}. {} ({})\n", idx + 1, watch.expression, mode_str));
        }

        Ok(output)
    }

    async fn handle_get_last_event(&self, _args: serde_json::Value) -> Result<String, String> {
        let session_guard = self.session_manager.get_current_session().await
            .ok_or_else(|| "No active debug session".to_string())?;

        let mut session = session_guard.lock().await;

        let event_set = match &session.last_event {
            Some(es) => es.clone(),
            None => return Ok("No events received yet. Set a breakpoint and trigger it.".to_string()),
        };

        let mut output = format!("Last event (suspend_policy={})\n\n", event_set.suspend_policy);

        for (idx, event) in event_set.events.iter().enumerate() {
            output.push_str(&format!("Event {}:\n", idx + 1));
            output.push_str(&format!("  Request ID: {}\n", event.request_id));

            match &event.details {
                jdwp_client::events::EventKind::Breakpoint { thread, location } => {
                    let (class_name, method_name, line) = resolve_location(&mut session, location).await;
                    let thread_info = format_thread_info(&mut session, *thread).await;
                    output.push_str("  Type: Breakpoint\n");
                    output.push_str(&format!("  {}\n", thread_info));
                    output.push_str(&format!("  Location: {}::{}() line {}\n", class_name, method_name, line));
                }
                jdwp_client::events::EventKind::Step { thread, location } => {
                    let (class_name, method_name, line) = resolve_location(&mut session, location).await;
                    let thread_info = format_thread_info(&mut session, *thread).await;
                    output.push_str("  Type: Step\n");
                    output.push_str(&format!("  {}\n", thread_info));
                    output.push_str(&format!("  Location: {}::{}() line {}\n", class_name, method_name, line));
                }
                jdwp_client::events::EventKind::VMStart { thread } => {
                    let thread_info = format_thread_info(&mut session, *thread).await;
                    output.push_str("  Type: VM Start\n");
                    output.push_str(&format!("  {}\n", thread_info));
                }
                jdwp_client::events::EventKind::VMDeath => {
                    output.push_str("  Type: VM Death\n");
                }
                jdwp_client::events::EventKind::ThreadStart { thread } => {
                    let thread_info = format_thread_info(&mut session, *thread).await;
                    output.push_str("  Type: Thread Start\n");
                    output.push_str(&format!("  {}\n", thread_info));
                }
                jdwp_client::events::EventKind::ThreadDeath { thread } => {
                    let thread_info = format_thread_info(&mut session, *thread).await;
                    output.push_str("  Type: Thread Death\n");
                    output.push_str(&format!("  {}\n", thread_info));
                }
                jdwp_client::events::EventKind::Exception { thread, location, exception, catch_location } => {
                    let (class_name, method_name, line) = resolve_location(&mut session, location).await;
                    let thread_info = format_thread_info(&mut session, *thread).await;
                    output.push_str("  Type: Exception\n");
                    output.push_str(&format!("  {}\n", thread_info));
                    output.push_str(&format!("  Thrown at: {}::{}() line {}\n", class_name, method_name, line));

                    // Try to get exception class name
                    if *exception != 0 {
                        if let Ok(exc_class_id) = session.connection.get_object_reference_type(*exception).await {
                            if let Ok(sig) = session.connection.get_signature(exc_class_id).await {
                                output.push_str(&format!("  Exception: {}\n", jvm_signature_to_class_name(&sig)));
                            }
                        }
                    }

                    match catch_location {
                        Some(catch_loc) => {
                            let (catch_class, catch_method, catch_line) = resolve_location(&mut session, catch_loc).await;
                            output.push_str(&format!("  Caught at: {}::{}() line {}\n", catch_class, catch_method, catch_line));
                        }
                        None => {
                            output.push_str("  Caught: uncaught\n");
                        }
                    }
                }
                jdwp_client::events::EventKind::ClassPrepare { thread, ref_type, signature, .. } => {
                    let thread_info = format_thread_info(&mut session, *thread).await;
                    output.push_str("  Type: Class Prepare\n");
                    output.push_str(&format!("  {}\n", thread_info));
                    output.push_str(&format!("  Class: {} (0x{:x})\n", signature, ref_type));
                }
                _ => {
                    output.push_str("  Type: Other\n");
                }
            }

            output.push_str("\n");
        }

        // Append watch results if present
        if let Some(watch_results) = &session.last_watch_results {
            if !watch_results.is_empty() {
                output.push_str("Watch expressions:\n");
                for (expr, val) in watch_results {
                    output.push_str(&format!("  {} = {}\n", expr, val));
                }
            }
        }

        Ok(output)
    }

    async fn handle_set_value(&self, args: serde_json::Value) -> Result<String, String> {
        let thread_id = parse_thread_id(&args)?;
        let frame_index = args.get("frame_index")
            .and_then(|v| v.as_i64())
            .unwrap_or(0) as i32;
        let variable_name = args.get("variable_name")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "Missing 'variable_name' parameter".to_string())?;
        let value_str = args.get("value")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "Missing 'value' parameter".to_string())?;

        let session_guard = self.session_manager.get_current_session().await
            .ok_or_else(|| "No active debug session".to_string())?;

        let mut session = session_guard.lock().await;

        // Get the frame
        let frames = session.connection.get_frames(thread_id, frame_index, 1).await
            .map_err(|e| format!("Failed to get frames: {}", e))?;
        let frame = frames.first()
            .ok_or_else(|| "No frame at specified index".to_string())?
            .clone();

        // Get variable table and find variable
        let var_table = session.connection.get_variable_table(
            frame.location.class_id, frame.location.method_id,
        ).await.map_err(|e| format!("Failed to get variable table: {}", e))?;

        let current_index = frame.location.index;
        let var = var_table.iter()
            .find(|v| v.name == variable_name && current_index >= v.code_index && current_index < v.code_index + v.length as u64)
            .ok_or_else(|| format!("Variable '{}' not found in current scope", variable_name))?
            .clone();

        // Get old value for display
        let old_value = {
            let slots = vec![jdwp_client::stackframe::VariableSlot {
                slot: var.slot as i32,
                sig_byte: var.signature.as_bytes()[0],
            }];
            let values = session.connection.get_frame_values(thread_id, frame.frame_id, slots).await
                .map_err(|e| format!("Failed to get current value: {}", e))?;
            values.into_iter().next()
                .ok_or_else(|| "No value returned for variable".to_string())?
        };
        let old_formatted = format_value_deep_with_thread(&mut session, &old_value, 200, thread_id).await;

        // Parse the new value based on variable signature
        let new_value = parse_value_literal(value_str, &var.signature, &mut session).await?;

        // Set the value
        session.connection.set_frame_values(
            thread_id,
            frame.frame_id,
            vec![(var.slot as i32, new_value.clone())],
        ).await.map_err(|e| format!("Failed to set value: {}", e))?;

        let new_formatted = format_value_deep_with_thread(&mut session, &new_value, 200, thread_id).await;

        Ok(format!(
            "Variable '{}' updated:\n  Old: {}\n  New: {}",
            variable_name, old_formatted, new_formatted
        ))
    }
}

// --- Helper functions ---

/// Parse a hex thread ID from tool arguments
fn parse_thread_id(args: &serde_json::Value) -> Result<u64, String> {
    let thread_id_str = args.get("thread_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "Missing 'thread_id' parameter".to_string())?;
    u64::from_str_radix(thread_id_str.trim_start_matches("0x"), 16)
        .map_err(|_| format!("Invalid thread_id: {}", thread_id_str))
}

/// Convert a JVM type signature to a human-readable class name
/// e.g., "Lcom/example/Foo;" -> "com.example.Foo"
fn jvm_signature_to_class_name(sig: &str) -> String {
    if sig.starts_with('L') && sig.ends_with(';') {
        sig[1..sig.len()-1].replace('/', ".")
    } else {
        sig.to_string()
    }
}

/// Resolve a JDWP Location to human-readable (class_name, method_name, line_number)
async fn resolve_location(
    session: &mut DebugSession,
    location: &jdwp_client::types::Location,
) -> (String, String, i32) {
    // Get class signature
    let class_name = match session.connection.get_signature(location.class_id).await {
        Ok(sig) => jvm_signature_to_class_name(&sig),
        Err(_) => format!("0x{:x}", location.class_id),
    };

    // Get method name and line number
    let (method_name, line) = match session.connection.get_methods(location.class_id).await {
        Ok(methods) => {
            if let Some(method) = methods.iter().find(|m| m.method_id == location.method_id) {
                let line = match session.connection.get_line_table(location.class_id, location.method_id).await {
                    Ok(line_table) => {
                        line_table.lines.iter()
                            .filter(|e| e.line_code_index <= location.index)
                            .max_by_key(|e| e.line_code_index)
                            .map(|e| e.line_number)
                            .unwrap_or(-1)
                    }
                    Err(_) => -1,
                };
                (method.name.clone(), line)
            } else {
                (format!("0x{:x}", location.method_id), -1)
            }
        }
        Err(_) => (format!("0x{:x}", location.method_id), -1),
    };

    (class_name, method_name, line)
}

/// Resolve a local variable by name from the current frame
async fn resolve_local_variable(
    session: &mut DebugSession,
    thread_id: u64,
    frame: &jdwp_client::thread::Frame,
    var_name: &str,
) -> Result<jdwp_client::types::Value, String> {
    // Get variable table
    let var_table = session.connection.get_variable_table(
        frame.location.class_id, frame.location.method_id,
    ).await.map_err(|e| format!("Failed to get variable table: {}", e))?;

    // Find variable by name in scope
    let current_index = frame.location.index;
    let var = var_table.iter()
        .find(|v| v.name == var_name && current_index >= v.code_index && current_index < v.code_index + v.length as u64)
        .ok_or_else(|| format!("Variable '{}' not found in current scope", var_name))?;

    // Get value
    let slots = vec![jdwp_client::stackframe::VariableSlot {
        slot: var.slot as i32,
        sig_byte: var.signature.as_bytes()[0],
    }];

    let values = session.connection.get_frame_values(thread_id, frame.frame_id, slots).await
        .map_err(|e| format!("Failed to get variable value: {}", e))?;

    values.into_iter().next()
        .ok_or_else(|| "No value returned for variable".to_string())
}

/// Evaluate a chained expression like "extraction.columns().size()" in the given frame context
async fn evaluate_expression(
    session: &mut DebugSession,
    thread_id: u64,
    frame_index: i32,
    expression: &str,
) -> Result<jdwp_client::types::Value, String> {
    // Get the frame
    let frames = session.connection.get_frames(thread_id, frame_index, 1).await
        .map_err(|e| format!("Failed to get frames: {}", e))?;
    let frame = frames.first()
        .ok_or_else(|| "No frame at specified index".to_string())?
        .clone();

    // Parse expression into segments: "a.b().c" -> ["a", "b()", "c"]
    let segments: Vec<&str> = expression.split('.').collect();
    if segments.is_empty() {
        return Err("Empty expression".to_string());
    }

    // Resolve first segment as local variable
    let mut current = resolve_local_variable(session, thread_id, &frame, segments[0]).await?;

    // Resolve each subsequent segment
    for segment in &segments[1..] {
        if segment.ends_with("()") {
            // Method invocation
            let method_name = &segment[..segment.len()-2];
            current = invoke_no_arg_method(session, thread_id, &current, method_name).await?;
        } else {
            // Try field access first; if not found, try as no-arg method (field-or-method fallback)
            match access_field(session, &current, segment).await {
                Ok(val) => current = val,
                Err(_) => {
                    current = invoke_no_arg_method(session, thread_id, &current, segment).await
                        .map_err(|_| format!("'{}' not found as field or method", segment))?;
                }
            }
        }
    }

    Ok(current)
}

/// Find a method by walking the superclass hierarchy, matching a signature prefix
async fn find_method_in_hierarchy(
    session: &mut DebugSession,
    mut class_id: u64,
    method_name: &str,
    sig_prefix: &str,
) -> Result<(u64, u64), String> {
    loop {
        let methods = session.connection.get_methods(class_id).await
            .map_err(|e| format!("Failed to get methods: {}", e))?;

        if let Some(method) = methods.iter().find(|m| m.name == method_name && m.signature.starts_with(sig_prefix)) {
            return Ok((class_id, method.method_id));
        }

        // Walk up to superclass
        let superclass_id = session.connection.get_superclass(class_id).await
            .map_err(|e| format!("Failed to get superclass: {}", e))?;

        if superclass_id == 0 {
            return Err(format!("Method '{}' with signature prefix '{}' not found in class hierarchy", method_name, sig_prefix));
        }

        class_id = superclass_id;
    }
}

/// Find a field by walking the superclass hierarchy
async fn find_field_in_hierarchy(
    session: &mut DebugSession,
    mut class_id: u64,
    field_name: &str,
) -> Result<u64, String> {
    loop {
        let fields = session.connection.get_fields(class_id).await
            .map_err(|e| format!("Failed to get fields: {}", e))?;

        if let Some(field) = fields.iter().find(|f| f.name == field_name) {
            return Ok(field.field_id);
        }

        // Walk up to superclass
        let superclass_id = session.connection.get_superclass(class_id).await
            .map_err(|e| format!("Failed to get superclass: {}", e))?;

        if superclass_id == 0 {
            return Err(format!("Field '{}' not found in class hierarchy", field_name));
        }

        class_id = superclass_id;
    }
}

/// Invoke a no-arg method on an object value (with hierarchy walking)
async fn invoke_no_arg_method(
    session: &mut DebugSession,
    thread_id: u64,
    value: &jdwp_client::types::Value,
    method_name: &str,
) -> Result<jdwp_client::types::Value, String> {
    let object_id = match &value.data {
        jdwp_client::types::ValueData::Object(id) => {
            if *id == 0 { return Err("Cannot invoke method on null".to_string()); }
            *id
        }
        _ => return Err("Cannot invoke method on non-object value".to_string()),
    };

    // Get class
    let class_id = session.connection.get_object_reference_type(object_id).await
        .map_err(|e| format!("Failed to get object type: {}", e))?;

    // Find method with hierarchy walking
    let (found_class_id, method_id) = find_method_in_hierarchy(session, class_id, method_name, "()").await?;

    // Invoke
    let (return_value, exception_id) = session.connection.invoke_object_method(
        object_id,
        thread_id,
        found_class_id,
        method_id,
        vec![],
        jdwp_client::object::invoke_options::INVOKE_SINGLE_THREADED,
    ).await.map_err(|e| format!("Failed to invoke method: {}", e))?;

    if exception_id != 0 {
        return Err(format!("Method threw exception (object ID: 0x{:x})", exception_id));
    }

    Ok(return_value)
}

/// Access a field on an object value (with hierarchy walking)
async fn access_field(
    session: &mut DebugSession,
    value: &jdwp_client::types::Value,
    field_name: &str,
) -> Result<jdwp_client::types::Value, String> {
    let object_id = match &value.data {
        jdwp_client::types::ValueData::Object(id) => {
            if *id == 0 { return Err("Cannot access field on null".to_string()); }
            *id
        }
        _ => return Err("Cannot access field on non-object value".to_string()),
    };

    // Get class
    let class_id = session.connection.get_object_reference_type(object_id).await
        .map_err(|e| format!("Failed to get object type: {}", e))?;

    // Find field with hierarchy walking
    let field_id = find_field_in_hierarchy(session, class_id, field_name).await?;

    // Get value
    let values = session.connection.get_object_values(object_id, vec![field_id]).await
        .map_err(|e| format!("Failed to get field value: {}", e))?;

    values.into_iter().next()
        .ok_or_else(|| "No value returned for field".to_string())
}

/// Check if a value is "truthy" for conditional breakpoint evaluation
async fn is_truthy(
    session: &mut DebugSession,
    value: &jdwp_client::types::Value,
) -> bool {
    match &value.data {
        jdwp_client::types::ValueData::Boolean(v) => *v,
        jdwp_client::types::ValueData::Int(v) => *v != 0,
        jdwp_client::types::ValueData::Long(v) => *v != 0,
        jdwp_client::types::ValueData::Short(v) => *v != 0,
        jdwp_client::types::ValueData::Byte(v) => *v != 0,
        jdwp_client::types::ValueData::Object(id) => {
            if *id == 0 {
                return false;
            }
            // For strings, check non-empty
            if value.tag == 115 {
                if let Ok(s) = session.connection.get_string_value(*id).await {
                    return !s.is_empty();
                }
            }
            true // non-null object is truthy
        }
        jdwp_client::types::ValueData::Void => false,
        jdwp_client::types::ValueData::Float(v) => *v != 0.0,
        jdwp_client::types::ValueData::Double(v) => *v != 0.0,
        jdwp_client::types::ValueData::Char(v) => *v != 0,
    }
}

/// Format a value with auto-stringify for objects
async fn format_value_deep(
    session: &mut DebugSession,
    value: &jdwp_client::types::Value,
    max_len: usize,
) -> String {
    // For string objects, dereference to show actual string
    if value.tag == 115 { // 's' = string
        if let jdwp_client::types::ValueData::Object(object_id) = &value.data {
            if *object_id == 0 {
                return "(String) null".to_string();
            }
            if let Ok(s) = session.connection.get_string_value(*object_id).await {
                let display = if s.len() > max_len {
                    format!("\"{}...\" (truncated)", &s[..max_len])
                } else {
                    format!("\"{}\"", s)
                };
                return format!("(String) {}", display);
            }
        }
    }

    // For non-null object types (L=76, t=116, g=103, l=108, c=99, [=91), auto-stringify
    if matches!(value.tag, 76 | 116 | 103 | 108 | 99 | 91) {
        if let jdwp_client::types::ValueData::Object(object_id) = &value.data {
            if *object_id == 0 {
                return "(object) null".to_string();
            }

            // Get class name
            let class_name = match session.connection.get_object_reference_type(*object_id).await {
                Ok(class_id) => match session.connection.get_signature(class_id).await {
                    Ok(sig) => jvm_signature_to_class_name(&sig),
                    Err(_) => "?".to_string(),
                },
                Err(_) => "?".to_string(),
            };

            // Try toString() via hierarchy walking
            let to_string_val = jdwp_client::types::Value {
                tag: value.tag,
                data: jdwp_client::types::ValueData::Object(*object_id),
            };
            // We need a thread to invoke toString - try to find one from the last event
            if let Some(thread_id) = get_suspended_thread(session) {
                if let Ok(result) = invoke_no_arg_method(session, thread_id, &to_string_val, "toString").await {
                    if result.tag == 115 { // string result
                        if let jdwp_client::types::ValueData::Object(str_id) = &result.data {
                            if *str_id != 0 {
                                if let Ok(s) = session.connection.get_string_value(*str_id).await {
                                    let display = if s.len() > max_len {
                                        format!("\"{}...\" (truncated)", &s[..max_len])
                                    } else {
                                        format!("\"{}\"", s)
                                    };
                                    return format!("({}) {}", class_name, display);
                                }
                            }
                        }
                    }
                }
            }

            // Fallback: class name + hex ID
            return format!("({}) @{:x}", class_name, object_id);
        }
    }

    // For primitives, use the standard format
    value.format()
}

/// Get a suspended thread ID from the session's last event
fn get_suspended_thread(session: &DebugSession) -> Option<u64> {
    if let Some(event_set) = &session.last_event {
        for event in &event_set.events {
            match &event.details {
                jdwp_client::events::EventKind::Breakpoint { thread, .. } => return Some(*thread),
                jdwp_client::events::EventKind::Step { thread, .. } => return Some(*thread),
                jdwp_client::events::EventKind::Exception { thread, .. } => return Some(*thread),
                _ => {}
            }
        }
    }
    None
}

/// Format a value with auto-stringify, using a known thread for toString() calls
async fn format_value_deep_with_thread(
    session: &mut DebugSession,
    value: &jdwp_client::types::Value,
    max_len: usize,
    thread_id: u64,
) -> String {
    // For string objects, dereference to show actual string
    if value.tag == 115 { // 's' = string
        if let jdwp_client::types::ValueData::Object(object_id) = &value.data {
            if *object_id == 0 {
                return "(String) null".to_string();
            }
            if let Ok(s) = session.connection.get_string_value(*object_id).await {
                let display = if s.len() > max_len {
                    format!("\"{}...\" (truncated)", &s[..max_len])
                } else {
                    format!("\"{}\"", s)
                };
                return format!("(String) {}", display);
            }
        }
    }

    // For non-null object types, auto-stringify
    if matches!(value.tag, 76 | 116 | 103 | 108 | 99 | 91) {
        if let jdwp_client::types::ValueData::Object(object_id) = &value.data {
            if *object_id == 0 {
                return "(object) null".to_string();
            }

            let class_name = match session.connection.get_object_reference_type(*object_id).await {
                Ok(class_id) => match session.connection.get_signature(class_id).await {
                    Ok(sig) => jvm_signature_to_class_name(&sig),
                    Err(_) => "?".to_string(),
                },
                Err(_) => "?".to_string(),
            };

            let to_string_val = jdwp_client::types::Value {
                tag: value.tag,
                data: jdwp_client::types::ValueData::Object(*object_id),
            };
            if let Ok(result) = invoke_no_arg_method(session, thread_id, &to_string_val, "toString").await {
                if result.tag == 115 {
                    if let jdwp_client::types::ValueData::Object(str_id) = &result.data {
                        if *str_id != 0 {
                            if let Ok(s) = session.connection.get_string_value(*str_id).await {
                                let display = if s.len() > max_len {
                                    format!("\"{}...\" (truncated)", &s[..max_len])
                                } else {
                                    format!("\"{}\"", s)
                                };
                                return format!("({}) {}", class_name, display);
                            }
                        }
                    }
                }
            }

            return format!("({}) @{:x}", class_name, object_id);
        }
    }

    value.format()
}

/// Format thread info with resolved name
async fn format_thread_info(session: &mut DebugSession, thread_id: u64) -> String {
    match session.connection.get_thread_name(thread_id).await {
        Ok(name) => format!("Thread: \"{}\" (0x{:x})", name, thread_id),
        Err(_) => format!("Thread: 0x{:x}", thread_id),
    }
}

/// Invoke a method with a single int argument on an object value
async fn invoke_method_with_int_arg(
    session: &mut DebugSession,
    thread_id: u64,
    value: &jdwp_client::types::Value,
    method_name: &str,
    int_arg: i32,
) -> Result<jdwp_client::types::Value, String> {
    let object_id = match &value.data {
        jdwp_client::types::ValueData::Object(id) => {
            if *id == 0 { return Err("Cannot invoke method on null".to_string()); }
            *id
        }
        _ => return Err("Cannot invoke method on non-object value".to_string()),
    };

    let class_id = session.connection.get_object_reference_type(object_id).await
        .map_err(|e| format!("Failed to get object type: {}", e))?;

    let (found_class_id, method_id) = find_method_in_hierarchy(session, class_id, method_name, "(I)").await?;

    let args = vec![jdwp_client::types::Value {
        tag: 73, // 'I' = int
        data: jdwp_client::types::ValueData::Int(int_arg),
    }];

    let (return_value, exception_id) = session.connection.invoke_object_method(
        object_id,
        thread_id,
        found_class_id,
        method_id,
        args,
        jdwp_client::object::invoke_options::INVOKE_SINGLE_THREADED,
    ).await.map_err(|e| format!("Failed to invoke method: {}", e))?;

    if exception_id != 0 {
        return Err(format!("Method threw exception (object ID: 0x{:x})", exception_id));
    }

    Ok(return_value)
}

/// Format collection/array elements individually
async fn format_collection_elements(
    session: &mut DebugSession,
    value: &jdwp_client::types::Value,
    thread_id: u64,
    max_elements: usize,
    max_element_len: usize,
) -> String {
    let object_id = match &value.data {
        jdwp_client::types::ValueData::Object(id) if *id != 0 => *id,
        _ => return format_value_deep_with_thread(session, value, 200, thread_id).await,
    };

    // Get class name
    let class_name = match session.connection.get_object_reference_type(object_id).await {
        Ok(class_id) => match session.connection.get_signature(class_id).await {
            Ok(sig) => jvm_signature_to_class_name(&sig),
            Err(_) => "?".to_string(),
        },
        Err(_) => "?".to_string(),
    };

    // Check if it's an array (tag = 91 = '[')
    if value.tag == 91 {
        match session.connection.get_array_length(object_id).await {
            Ok(length) => {
                let fetch_count = std::cmp::min(length as usize, max_elements) as i32;
                let mut output = format!("(array, length={})\n", length);

                match session.connection.get_array_values(object_id, 0, fetch_count).await {
                    Ok(elements) => {
                        for (i, elem) in elements.iter().enumerate() {
                            let formatted = format_value_deep_with_thread(session, elem, max_element_len, thread_id).await;
                            output.push_str(&format!("  [{}] = {}\n", i, formatted));
                        }
                        if length as usize > max_elements {
                            output.push_str(&format!("  ... ({} more)\n", length as usize - max_elements));
                        }
                    }
                    Err(e) => {
                        output.push_str(&format!("  <error reading elements: {}>\n", e));
                    }
                }

                return output;
            }
            Err(_) => {} // Not actually an array, try collection path
        }
    }

    // Try List-like collection: call size() then get(int)
    let size_result = invoke_no_arg_method(session, thread_id, value, "size").await;
    if let Ok(size_val) = size_result {
        if let jdwp_client::types::ValueData::Int(size) = &size_val.data {
            let fetch_count = std::cmp::min(*size as usize, max_elements);
            let mut output = format!("({}, size={})\n", class_name, size);

            for i in 0..fetch_count {
                match invoke_method_with_int_arg(session, thread_id, value, "get", i as i32).await {
                    Ok(elem) => {
                        let formatted = format_value_deep_with_thread(session, &elem, max_element_len, thread_id).await;
                        output.push_str(&format!("  [{}] = {}\n", i, formatted));
                    }
                    Err(e) => {
                        output.push_str(&format!("  [{}] = <error: {}>\n", i, e));
                    }
                }
            }
            if *size as usize > max_elements {
                output.push_str(&format!("  ... ({} more)\n", *size as usize - max_elements));
            }

            return output;
        }
    }

    // Fallback to toString
    format_value_deep_with_thread(session, value, 200, thread_id).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn jvm_signature_standard_class() {
        assert_eq!(jvm_signature_to_class_name("Lcom/example/Foo;"), "com.example.Foo");
    }

    #[test]
    fn jvm_signature_java_lang_string() {
        assert_eq!(jvm_signature_to_class_name("Ljava/lang/String;"), "java.lang.String");
    }

    #[test]
    fn jvm_signature_primitive_passthrough() {
        assert_eq!(jvm_signature_to_class_name("I"), "I");
    }

    #[test]
    fn jvm_signature_nested_class() {
        assert_eq!(jvm_signature_to_class_name("Lcom/example/Foo$Bar;"), "com.example.Foo$Bar");
    }

    #[test]
    fn parse_thread_id_hex_prefix() {
        let args = json!({"thread_id": "0x8"});
        assert_eq!(parse_thread_id(&args).unwrap(), 8);
    }

    #[test]
    fn parse_thread_id_hex_ff() {
        let args = json!({"thread_id": "0xff"});
        assert_eq!(parse_thread_id(&args).unwrap(), 255);
    }

    #[test]
    fn parse_thread_id_no_prefix() {
        let args = json!({"thread_id": "8"});
        assert_eq!(parse_thread_id(&args).unwrap(), 8);
    }

    #[test]
    fn parse_thread_id_missing_key() {
        let args = json!({});
        assert!(parse_thread_id(&args).is_err());
    }

    #[test]
    fn parse_thread_id_invalid_value() {
        let args = json!({"thread_id": "not_hex_zz"});
        assert!(parse_thread_id(&args).is_err());
    }
}

/// Parse a value literal string into a JDWP Value based on the variable's type signature
async fn parse_value_literal(
    value_str: &str,
    signature: &str,
    session: &mut DebugSession,
) -> Result<jdwp_client::types::Value, String> {
    let trimmed = value_str.trim();

    // String literal: starts and ends with quotes
    if trimmed.starts_with('"') && trimmed.ends_with('"') {
        let string_content = &trimmed[1..trimmed.len()-1];
        let string_id = session.connection.create_string(string_content).await
            .map_err(|e| format!("Failed to create string in JVM: {}", e))?;
        return Ok(jdwp_client::types::Value {
            tag: 115, // 's' = string
            data: jdwp_client::types::ValueData::Object(string_id),
        });
    }

    // Boolean
    if trimmed == "true" || trimmed == "false" {
        return Ok(jdwp_client::types::Value {
            tag: 90, // 'Z' = boolean
            data: jdwp_client::types::ValueData::Boolean(trimmed == "true"),
        });
    }

    // null
    if trimmed == "null" {
        // Determine the right tag from signature
        let tag = match signature.as_bytes().first() {
            Some(b'L') | Some(b'[') => 76_u8, // 'L' = object
            _ => 76,
        };
        return Ok(jdwp_client::types::Value {
            tag,
            data: jdwp_client::types::ValueData::Object(0),
        });
    }

    // Numeric types — match based on variable signature
    let sig_char = signature.as_bytes().first()
        .ok_or_else(|| "Empty variable signature".to_string())?;

    match sig_char {
        b'I' => {
            let v: i32 = trimmed.parse()
                .map_err(|_| format!("Cannot parse '{}' as int", trimmed))?;
            Ok(jdwp_client::types::Value { tag: 73, data: jdwp_client::types::ValueData::Int(v) })
        }
        b'J' => {
            let v: i64 = trimmed.parse()
                .map_err(|_| format!("Cannot parse '{}' as long", trimmed))?;
            Ok(jdwp_client::types::Value { tag: 74, data: jdwp_client::types::ValueData::Long(v) })
        }
        b'S' => {
            let v: i16 = trimmed.parse()
                .map_err(|_| format!("Cannot parse '{}' as short", trimmed))?;
            Ok(jdwp_client::types::Value { tag: 83, data: jdwp_client::types::ValueData::Short(v) })
        }
        b'B' => {
            let v: i8 = trimmed.parse()
                .map_err(|_| format!("Cannot parse '{}' as byte", trimmed))?;
            Ok(jdwp_client::types::Value { tag: 66, data: jdwp_client::types::ValueData::Byte(v) })
        }
        b'F' => {
            let v: f32 = trimmed.parse()
                .map_err(|_| format!("Cannot parse '{}' as float", trimmed))?;
            Ok(jdwp_client::types::Value { tag: 70, data: jdwp_client::types::ValueData::Float(v) })
        }
        b'D' => {
            let v: f64 = trimmed.parse()
                .map_err(|_| format!("Cannot parse '{}' as double", trimmed))?;
            Ok(jdwp_client::types::Value { tag: 68, data: jdwp_client::types::ValueData::Double(v) })
        }
        b'C' => {
            let c = trimmed.chars().next()
                .ok_or_else(|| "Empty char value".to_string())?;
            Ok(jdwp_client::types::Value { tag: 67, data: jdwp_client::types::ValueData::Char(c as u16) })
        }
        b'Z' => {
            let v = trimmed == "true" || trimmed == "1";
            Ok(jdwp_client::types::Value { tag: 90, data: jdwp_client::types::ValueData::Boolean(v) })
        }
        b'L' if signature.contains("String") => {
            // String type but value wasn't quoted — create string anyway
            let string_id = session.connection.create_string(trimmed).await
                .map_err(|e| format!("Failed to create string in JVM: {}", e))?;
            Ok(jdwp_client::types::Value {
                tag: 115,
                data: jdwp_client::types::ValueData::Object(string_id),
            })
        }
        _ => Err(format!("Unsupported variable type signature '{}' for value '{}'", signature, trimmed)),
    }
}
