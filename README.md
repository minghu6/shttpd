
## Usage

### Set Log Level

Log Level: `RUST_LOG`

### CGI Spec

Persistent Directory: `SHTTPD_PERSIS_DIR`

Query Parameter `XX`: `SHTTPD_Q_XX`

### Test

*When running sttpd during vscode container, there is "No New Privilge" issue, run in normal shell or start code with `--no-sandbox`.*

recommend `httpie` (python http client terminal app) to test sttpd

### Debug

Use remote debug to bypass privilege restrict.

1. start server
`sudo lldb-server platform --server --listen 0.0.0.0:8081`

2. launch.json config

```json
"initCommands": [
    "platform select remote-linux", // For example: 'remote-linux', 'remote-macosx', 'remote-android', etc.
    "platform connect connect://localhost:8081",
    "settings set target.inherit-env true", // See note below.
],
```
