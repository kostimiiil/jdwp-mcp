// Debug session management
//
// Manages JDWP connection state, breakpoints, and thread tracking

use jdwp_client::{JdwpConnection, EventSet};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tokio::sync::mpsc;

pub type SessionId = String;

#[derive(Debug)]
pub struct DebugSession {
    pub connection: JdwpConnection,
    pub breakpoints: HashMap<String, BreakpointInfo>,
    pub threads: HashMap<String, ThreadInfo>,
    pub last_event: Option<EventSet>,
    pub step_event_tx: Option<mpsc::Sender<EventSet>>,
    pub event_listener_task: Option<JoinHandle<()>>,
    pub watch_expressions: Vec<WatchExpression>,
    pub last_watch_results: Option<Vec<(String, String)>>,
}

#[derive(Debug, Clone)]
pub struct BreakpointInfo {
    pub id: String,
    pub request_id: i32,
    pub class_pattern: String,
    pub line: u32,
    pub method: Option<String>,
    pub enabled: bool,
    pub hit_count: u32,
    pub exception_class: Option<String>,
    pub condition: Option<String>,
    pub skip_count: u32,
    pub package_filter: Option<String>,
}

#[derive(Debug, Clone)]
pub struct WatchExpression {
    pub expression: String,
    pub evaluate_on: WatchMode,
}

#[derive(Debug, Clone, PartialEq)]
pub enum WatchMode {
    Steps,
    BreakpointsOnly,
}

#[derive(Debug, Clone)]
pub struct ThreadInfo {
    pub id: String,
    pub name: String,
    pub status: String,
    pub suspended: bool,
}

#[derive(Clone)]
pub struct SessionManager {
    sessions: Arc<Mutex<HashMap<SessionId, Arc<Mutex<DebugSession>>>>>,
    current_session: Arc<Mutex<Option<SessionId>>>,
}

impl SessionManager {
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(Mutex::new(HashMap::new())),
            current_session: Arc::new(Mutex::new(None)),
        }
    }

    pub async fn create_session(&self, connection: JdwpConnection) -> SessionId {
        let session_id = format!("session_{}", uuid::v4());
        let session = DebugSession {
            connection,
            breakpoints: HashMap::new(),
            threads: HashMap::new(),
            last_event: None,
            step_event_tx: None,
            event_listener_task: None,
            watch_expressions: Vec::new(),
            last_watch_results: None,
        };

        let mut sessions = self.sessions.lock().await;
        sessions.insert(session_id.clone(), Arc::new(Mutex::new(session)));

        // Set as current session
        let mut current = self.current_session.lock().await;
        *current = Some(session_id.clone());

        session_id
    }

    pub async fn get_current_session(&self) -> Option<Arc<Mutex<DebugSession>>> {
        let current = self.current_session.lock().await;
        if let Some(session_id) = current.as_ref() {
            let sessions = self.sessions.lock().await;
            sessions.get(session_id).cloned()
        } else {
            None
        }
    }

    pub async fn get_current_session_id(&self) -> Option<SessionId> {
        let current = self.current_session.lock().await;
        current.clone()
    }

    pub async fn remove_session(&self, session_id: &str) {
        let mut sessions = self.sessions.lock().await;

        // Abort the event listener task if it exists
        if let Some(session_arc) = sessions.get(session_id) {
            let mut session = session_arc.lock().await;
            if let Some(task) = session.event_listener_task.take() {
                task.abort();
            }
        }

        sessions.remove(session_id);

        // Clear current if it was this session
        let mut current = self.current_session.lock().await;
        if current.as_ref() == Some(&session_id.to_string()) {
            *current = None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn watch_mode_inequality() {
        assert_ne!(WatchMode::Steps, WatchMode::BreakpointsOnly);
    }

    #[test]
    fn watch_mode_equality() {
        assert_eq!(WatchMode::Steps, WatchMode::Steps);
        assert_eq!(WatchMode::BreakpointsOnly, WatchMode::BreakpointsOnly);
    }

    #[test]
    fn watch_expression_clone() {
        let original = WatchExpression {
            expression: "myVar.size()".to_string(),
            evaluate_on: WatchMode::Steps,
        };
        let cloned = original.clone();
        assert_eq!(cloned.expression, "myVar.size()");
        assert_eq!(cloned.evaluate_on, WatchMode::Steps);
    }

    #[test]
    fn breakpoint_info_new_fields() {
        let bp = BreakpointInfo {
            id: "bp_1".to_string(),
            request_id: 42,
            class_pattern: "com.example.Foo".to_string(),
            line: 10,
            method: Some("bar".to_string()),
            enabled: true,
            hit_count: 0,
            exception_class: None,
            condition: Some("x > 5".to_string()),
            skip_count: 3,
            package_filter: Some("com.example".to_string()),
        };
        assert_eq!(bp.skip_count, 3);
        assert_eq!(bp.package_filter.as_deref(), Some("com.example"));
        assert_eq!(bp.condition.as_deref(), Some("x > 5"));
    }
}

// Simple UUID generation for session IDs
mod uuid {
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(1);

    pub fn v4() -> String {
        let counter = COUNTER.fetch_add(1, Ordering::SeqCst);
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis();

        format!("{:x}{:x}", timestamp, counter)
    }
}
