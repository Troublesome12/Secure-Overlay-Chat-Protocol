"""Protocol constants and error codes for SOCP (v1.1)"""

# --- Presence & user list ---
T_USER_ADVERTISE   = "USER_ADVERTISE"
T_USER_REMOVE      = "USER_REMOVE"
T_USER_LIST_REQ    = "USER_LIST_REQ"    # client -> server (ask for known-online users)
T_USER_LIST        = "USER_LIST"        # server -> client (reply with list)
T_DB_USER          = "DB_USER"          # server(master)->server(local) reply for DB_GET_USER

# --- User <-> Server (unchanged for DM, files) ---
T_USER_HELLO       = "USER_HELLO"
T_MSG_PRIVATE      = "MSG_PRIVATE"
T_USER_DELIVER     = "USER_DELIVER"
T_USER_DB_GET      = "USER_DB_GET"
T_USER_DB_USER     = "USER_DB_USER"
T_ERROR            = "ERROR"

# --- Server <-> Server (unchanged for DM routing & DB) ---
T_PEER_HELLO_LINK  = "PEER_HELLO_LINK"
T_PEER_DELIVER     = "PEER_DELIVER" 
T_DB_GET_USER      = "DB_GET_USER"
T_DB_REGISTER      = "DB_REGISTER"

# --- Public channel ---
T_PUBLIC_POST      = "PUBLIC_POST"
CHANNEL_PUBLIC = "public"

# Optional: public presence broadcast (server->user for UI); not required for basic post delivery.
T_PUBLIC_INFO      = "PUBLIC_INFO"      # (optional UI hints, not used in routing)
T_HEARTBEAT        = "HEARTBEAT"

# --- Files (unchanged) ---
T_FILE_START       = "FILE_START"
T_FILE_CHUNK       = "FILE_CHUNK"
T_FILE_END         = "FILE_END"

# --- Error codes (unchanged) ---
E_USER_NOT_FOUND   = "USER_NOT_FOUND"
E_INVALID_SIG      = "INVALID_SIG"
E_BAD_KEY          = "BAD_KEY"
E_TIMEOUT          = "TIMEOUT"
E_UNKNOWN_TYPE     = "UNKNOWN_TYPE"
E_NAME_IN_USE      = "NAME_IN_USE"
