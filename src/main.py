import argparse
import asyncio
import pathlib
import uuid

from typing import Optional


"""
CLI entrypoint for SOCP Chat (flat src layout) with:
- Role-based UUID management (master/local)
- UUID generators (`gen master` / `gen local`)
- Deferred imports so `gen` works without installing deps
- Automatic key paths:
    * Server:  keys/<server_uuid>.pem   (if --keys not provided)
    * Client:  keys/<user_uuid>.pem     (if --keys not provided)
"""

# -------- UUID helpers --------

def _load_text(path: pathlib.Path) -> Optional[str]:
    """Reads the full contents of a text file, if it exists

    Args:
        path (pathlib.Path): Path to the file

    Returns:
        Optional[str]: Stripped file contents if present; otherwise None
    """

    if path.exists():
        return path.read_text().strip()
    return None

def _save_text(path: pathlib.Path, text: str) -> None:
    """Writes text to a file, creating parent directories if needed

    Args:
        path (pathlib.Path): Destination file path
        text (str): Text content to write

    Returns:
        None
    """

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)

DEF_MASTER_UUID_FILE = pathlib.Path("keys/master.uuid")
DEF_SERVER_UUID_FILE = pathlib.Path("keys/server.uuid")

def ensure_master_uuid(provided: Optional[str] = None, file: pathlib.Path = DEF_MASTER_UUID_FILE) -> str:
    """Ensures a stable Master UUID (prefix `master_server_`) exists and returns it

    If `provided` is given, it is normalized to include the `master_server_` prefix
    and persisted to `file`. If not provided, the function loads from `file` or
    generates a new UUID with the correct prefix and saves it

    Args:
        provided (Optional[str]): Existing UUID (with or without prefix). Defaults to None
        file (pathlib.Path): Storage location for the master UUID. Defaults to DEF_MASTER_UUID_FILE

    Returns:
        str: The resolved Master UUID (format: `master_server_<uuid4>`)
    """

    if provided:
        if not provided.startswith("master_server_"):
            # normalize if caller passed a bare UUID
            provided = f"master_server_{provided}"
        _save_text(file, provided)
        return provided
    current = _load_text(file)
    if current:
        return current
    newu = f"master_server_{uuid.uuid4()}"
    _save_text(file, newu)
    return newu

def ensure_local_uuid(file: pathlib.Path = DEF_SERVER_UUID_FILE) -> str:
    """Ensures a stable Local Server UUID (prefix `server_`) exists and returns it

        Loads from `file` if present; otherwise generates a new UUID with the `server_`
        prefix and persists it.

    Args:
        file (pathlib.Path): Storage location for the local server UUID. Defaults to DEF_SERVER_UUID_FILE

    Returns:
        str: The resolved Local Server UUID (format: `server_<uuid4>`)
    """

    current = _load_text(file)
    if current:
        return current
    newu = f"server_{uuid.uuid4()}"
    _save_text(file, newu)
    return newu

# -------- CLI --------

def main() -> None:
    """Parses CLI arguments and runs the requested subcommand

    Subcommands
    -----------
    gen
        Generate and persist UUIDs
        - `gen master [--file <path>]` -> writes/prints a `master_server_<uuid>`
        - `gen local  [--file <path>]` -> writes/prints a `server_<uuid>`
    server
        Run a mesh server (Master or Local)
        Required:
            --role {master,local}
            --listen <host:port>
        Optional:
            --peers ws://host:port ...
            --master-url ws://host:port (appended to peers)
            --keys <pem>  (default: keys/<server_uuid>.pem)
            --db <path>   (Master JSON DB path)
            --server-uuid / --master-uuid (advanced overrides)
            --server-uuid-file / --master-uuid-file (where UUIDs persist)
    client
        Run a user client
        Required:
            --user-uuid <id>
            --server ws://host:port
        Optional:
            --keys <pem>  (default: keys/<user_uuid>.pem)

    Raises:
        SystemExit: For invalid configuration (e.g., missing Master UUID when starting a local)
        Exception: Propagated runtime errors from server/client execution
    """

    ap = argparse.ArgumentParser(description="SOCP Chat v1.1")
    sub = ap.add_subparsers(dest="cmd", required=True)

    # Generators
    g = sub.add_parser("gen", help="Generate and persist UUIDs")
    g.add_argument("which", choices=["master", "local"], help="Type of UUID to generate")
    g.add_argument("--file", default=None,
                   help="Optional output file (defaults to keys/master.uuid or keys/server.uuid)")

    # Server
    s = sub.add_parser("server", help="Run a mesh server")
    s.add_argument("--role", choices=["master", "local"], required=True)
    s.add_argument("--listen", required=True, help="host:port")
    s.add_argument("--peers", nargs='*', default=[], help="ws://host:port peers")
    s.add_argument("--master-url", default=None,
                   help="ws://host:port of Master; appended to peers for convenience")
    s.add_argument("--keys", default=None,
                   help="PEM path; default: keys/<server_uuid>.pem")
    s.add_argument("--db", default="data/master_db.json")
    # Optional overrides (advanced)
    s.add_argument("--server-uuid", default=None)
    s.add_argument("--master-uuid", default=None)
    s.add_argument("--server-uuid-file", default=str(DEF_SERVER_UUID_FILE))
    s.add_argument("--master-uuid-file", default=str(DEF_MASTER_UUID_FILE))

    # Client
    c = sub.add_parser("client", help="Run a user client")
    c.add_argument("--user-uuid", required=True)
    c.add_argument("--server", required=True, help="ws://host:port of local server")
    c.add_argument("--keys", default=None,
                   help="PEM path; default: keys/<user_uuid>.pem")

    args = ap.parse_args()

    if args.cmd == "gen":
        file = pathlib.Path(args.file) if args.file else (
            DEF_MASTER_UUID_FILE if args.which == "master" else DEF_SERVER_UUID_FILE
        )
        if args.which == "master":
            val = ensure_master_uuid(file=file)
        else:
            val = ensure_local_uuid(file=file)
        print(val)
        return

    if args.cmd == "server":
        # Defer heavy import so `gen` doesn't require dependencies
        from server import SOCPServer  # type: ignore

        # Build peer list
        peers = list(args.peers)
        if args.master_url and args.master_url not in peers:
            peers.append(args.master_url)

        # Resolve UUIDs by role
        master_file = pathlib.Path(args.master_uuid_file)
        server_file = pathlib.Path(args.server_uuid_file)

        if args.role == "master":
            master_uuid = ensure_master_uuid(provided=args.master_uuid, file=master_file)
            server_uuid = args.server_uuid or master_uuid  # server_uuid == master_uuid
            # Do NOT write master UUID into server_uuid_file to avoid locals reusing it
        else:  # local
            master_uuid = args.master_uuid or _load_text(master_file)
            if not master_uuid:
                raise SystemExit(
                    "Master UUID not found. Run 'python src/main.py gen master' on the master first, "
                    "or pass --master-uuid."
                )
            server_uuid = args.server_uuid or ensure_local_uuid(file=server_file)

        # Automatic key path if not provided: keys/<server_uuid>.pem
        key_path = pathlib.Path(args.keys) if args.keys else pathlib.Path("keys") / f"{server_uuid}.pem"

        srv = SOCPServer(
            server_uuid=server_uuid,
            master_uuid=master_uuid,
            listen=args.listen,
            key_path=key_path,
            peer_urls=peers,
            db_path=pathlib.Path(args.db),
        )
        asyncio.run(srv.run())
        return

    if args.cmd == "client":
        # Defer heavy import so `gen` doesn't require dependencies
        from client import SOCPClient  # type: ignore

        # Automatic key path if not provided: keys/<user_uuid>.pem
        key_path = pathlib.Path(args.keys) if args.keys else pathlib.Path("keys") / f"{args.user_uuid}.pem"

        cli = SOCPClient(
            user_uuid=args.user_uuid,
            server_url=args.server,
            key_path=key_path,
        )
        asyncio.run(cli.run())
        return

if __name__ == "__main__":
    main()
