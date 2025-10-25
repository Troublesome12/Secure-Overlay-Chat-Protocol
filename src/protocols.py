# --- Presence & user list ---
T_USER_ADVERTISE            = "USER_ADVERTISE"
T_USER_REMOVE               = "USER_REMOVE"
T_USER_LIST_REQ             = "USER_LIST_REQ"    # client -> server (ask for known-online users)
T_USER_LIST                 = "USER_LIST"        # server -> client (reply with list)
T_DB_USER                   = "DB_USER"          # server(master)->server(local) reply for DB_GET_USER

# --- User <-> Server (unchanged for DM, files) ---
T_USER_HELLO                = "USER_HELLO"
T_MSG_DIRECT                = "MSG_DIRECT"
T_USER_DELIVER              = "USER_DELIVER"
T_USER_DB_GET               = "USER_DB_GET"
T_USER_DB_USER              = "USER_DB_USER"
T_ERROR                     = "ERROR"

# --- Server <-> Server (unchanged for DM routing & DB) ---
T_SERVER_HELLO_JOIN         = "SERVER_HELLO_JOIN"   # dialer -> acceptor (includes pubkey, addr, role)
T_SERVER_WELCOME            = "SERVER_WELCOME"      # acceptor -> dialer (confirms uuid, returns acceptor pubkey, addr, role)
T_SERVER_ANNOUNCE           = "SERVER_ANNOUNCE"     # any -> peers (introduce/refresh a 3rd peer: uuid, pubkey, addr, role)
T_SERVER_DELIVER            = "SERVER_DELIVER" 
T_PEER_HELLO_LINK           = "PEER_HELLO_LINK"
T_PEER_DELIVER              = "PEER_DELIVER" 
T_DB_GET_USER               = "DB_GET_USER"
T_DB_REGISTER               = "DB_REGISTER"

# --- Public channel ---
T_PUBLIC_CHANNEL_ADD        = "PUBLIC_CHANNEL_ADD"
T_PUBLIC_CHANNEL_UPDATED    = "PUBLIC_CHANNEL_UPDATED"
T_PUBLIC_CHANNEL_KEY_SHARE  = "PUBLIC_CHANNEL_KEY_SHARE"
T_MSG_PUBLIC_CHANNEL        = "MSG_PUBLIC_CHANNEL"
CHANNEL_PUBLIC              = "public"

# Optional: public presence broadcast (server->user for UI); not required for basic post delivery.
T_HEARTBEAT                 = "HEARTBEAT"

# --- Files ---
T_FILE_START                = "FILE_START"
T_FILE_CHUNK                = "FILE_CHUNK"
T_FILE_END                  = "FILE_END"

# --- Error codes ---
E_USER_NOT_FOUND            = "USER_NOT_FOUND"
E_TIMEOUT                   = "TIMEOUT"
E_UNKNOWN_TYPE              = "UNKNOWN_TYPE"
E_NAME_IN_USE               = "NAME_IN_USE"
