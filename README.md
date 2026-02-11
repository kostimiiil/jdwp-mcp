# jdwp-mcp

**Java debugging for LLMs via JDWP and Model Context Protocol**

An MCP server that enables Claude Code and other LLM tools to debug Java
applications through the Java Debug Wire Protocol (JDWP). Attach to running
JVMs, set breakpoints, inspect variables, and step through code—all through
natural language.

## Features

- **Remote Debugging**: Connect to any JVM started with JDWP enabled
- **Breakpoint Management**: Set, list, and clear breakpoints by class and line
- **Stack Inspection**: Get summarized stack frames with local variables
- **Execution Control**: Step over/into/out, continue, pause
- **Expression Evaluation**: Chained expressions like `obj.getList().size()` with superclass hierarchy walking
- **Exception Breakpoints**: Break on thrown exceptions by class or catch all
- **Conditional Breakpoints**: Only break when an expression evaluates to truthy
- **Watch Expressions**: Track expressions across steps
- **Thread Management**: List and control thread execution
- **Smart Summarization**: Auto-stringifies objects via `toString()`, shows readable values everywhere

## Quick Start

### 1. Start your Java app with JDWP enabled

```bash
java -agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=*:5005 -jar myapp.jar
```

### 2. Build the MCP server

```bash
cargo build --release
```

### 3. Configure Claude Code

The easiest way to enable the MCP server for your project:

```bash
# From your Java project directory
claude mcp add --scope project jdwp /path/to/jdwp-mcp/target/release/jdwp-mcp
```

Adjust the path to match where you cloned this repository. The `--scope project` flag makes the debugger available only in your current Java project.

**Alternative**: Manual configuration via `.mcp.json`:

```json
{
  "mcpServers": {
    "jdwp": {
      "command": "/path/to/jdwp-mcp/target/release/jdwp-mcp"
    }
  }
}
```

### 4. Debug with natural language

```
> Attach to the JVM at localhost:5005
> Set a breakpoint at com.example.HelloController line 65
> When it hits, show me the stack and the value of requestCount
```

## Available Tools

| Tool | Description |
|------|-------------|
| `debug.attach` | Connect to JVM via JDWP |
| `debug.set_breakpoint` | Set breakpoint at class:line (optional `condition`) |
| `debug.set_exception_breakpoint` | Break on exceptions (`"*"` for all, or specific class) |
| `debug.list_breakpoints` | List active breakpoints |
| `debug.clear_breakpoint` | Remove a breakpoint |
| `debug.continue` | Resume execution |
| `debug.step_over` | Step over current line |
| `debug.step_into` | Step into method |
| `debug.step_out` | Step out of method |
| `debug.get_stack` | Get stack frames with auto-stringified variables |
| `debug.evaluate` | Evaluate chained expressions (e.g. `obj.getList().size()`) |
| `debug.add_watch` | Add a watch expression evaluated on each step |
| `debug.remove_watch` | Remove a watch expression |
| `debug.list_watches` | List all watch expressions |
| `debug.list_threads` | List all threads |
| `debug.pause` | Pause execution |
| `debug.set_value` | Modify a local variable in the current frame |
| `debug.get_last_event` | Get last event (breakpoint, step, exception) |
| `debug.disconnect` | End debug session |

## Example: Debugging with kubectl port-forward

For Kubernetes-deployed Java apps:

```bash
# Forward JDWP port from pod
kubectl port-forward pod/my-app-pod 5005:5005
```

Then in Claude Code:
```
> Attach to localhost:5005
> Set a breakpoint in the processRequest method
```

## Architecture

```
Claude Code → MCP Server → JDWP Client → TCP Socket → JVM
                ↓
         Summarization &
         Context Filtering
```

The MCP server handles:
- **Protocol Translation**: MCP JSON-RPC ↔ JDWP binary protocol
- **Smart Summarization**: Truncates large objects, limits depth
- **State Management**: Tracks breakpoints, threads, sessions

## Development

### Project Structure

```
jdwp-mcp/
├── jdwp-client/        # JDWP protocol implementation
│   ├── connection.rs   # TCP + handshake
│   ├── protocol.rs     # Packet encoding/decoding
│   ├── commands.rs     # JDWP command constants
│   ├── types.rs        # JDWP type definitions
│   ├── events.rs       # Event handling
│   ├── eventrequest.rs # Breakpoint/step/exception requests
│   ├── stackframe.rs   # Frame value get/set
│   ├── object.rs       # Object field access + method invocation
│   ├── string.rs       # String value retrieval
│   ├── array.rs        # Array length + element access
│   ├── vm.rs           # VM-level commands (version, threads, create string)
│   ├── reftype.rs      # Class signature, methods, fields
│   └── thread.rs       # Thread name, frames, suspend
├── mcp-server/         # MCP server
│   ├── main.rs         # Stdio transport
│   ├── protocol.rs     # MCP JSON-RPC
│   ├── handlers.rs     # Request routing + expression evaluation
│   ├── tools.rs        # Tool definitions (19 tools)
│   └── session.rs      # Debug session state
└── examples/           # Integration test examples (require live JVM)
```

### Building & Testing

```bash
cargo build --release   # Release build
cargo test              # Run unit tests (~50 tests)
```

Unit tests cover protocol constants, packet construction, value formatting,
handler helpers, tool schemas, and session types. No JVM required.

#### Integration Testing

For end-to-end testing against a live JVM, use the companion
[java-example-for-k8s](../java-example-for-k8s):

```bash
cd ../java-example-for-k8s
mvn clean package
java -agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=*:5005 \
  -jar target/probe-demo-0.0.1-SNAPSHOT.jar
```

Then run the examples in `examples/` against the running app.

## Status

✅ **Core Functionality Complete** - Ready for MCP integration

### Implemented Features
- [x] Project structure
- [x] JDWP protocol (handshake, packets, encoding/decoding)
- [x] MCP server with 19 debug tools
- [x] VirtualMachine commands (Version, IDSizes, AllThreads, Suspend/Resume)
- [x] ClassesBySignature (find classes by name)
- [x] ReferenceType.Methods (get method info)
- [x] Method.LineTable (map source lines to bytecode)
- [x] Method.VariableTable (get variable metadata)
- [x] EventRequest.Set (breakpoints with location modifiers)
- [x] ThreadReference.Frames (get call stacks)
- [x] StackFrame.GetValues (read variable values)
- [x] Value formatting and display
- [x] Architecture independence (big-endian protocol, works on Intel & ARM M1/M2/M3)

### Working Examples
- [x] `test_connection` - Basic JDWP handshake
- [x] `test_vm_commands` - Query JVM version and ID sizes
- [x] `test_find_class` - Find classes and methods with line tables
- [x] `test_breakpoint` - Set breakpoints at specific source lines
- [x] `test_manual_stack` - Suspend and inspect thread stacks with variables

### Recent Additions
- [x] Chained expression evaluation (`a.b().c()`)
- [x] Superclass hierarchy walking for methods and fields
- [x] Auto-stringify object values via `toString()`
- [x] Exception breakpoints with package filter
- [x] Conditional breakpoints with skip count
- [x] Watch expressions (on steps or breakpoints only)
- [x] Variable modification (`debug.set_value`)
- [x] Collection/array element enumeration (`format_mode: "elements"`)
- [x] Unit test suite (~50 tests)

## References

- [JDWP Specification](https://docs.oracle.com/javase/8/docs/platform/jpda/jdwp/jdwp-protocol.html)
- [Model Context Protocol](https://modelcontextprotocol.io/)
- [Claude Code MCP Documentation](https://docs.claude.com/claude-code)

## License

MIT
