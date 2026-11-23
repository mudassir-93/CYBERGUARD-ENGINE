import os
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


class CyberGuardHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(ROOT), **kwargs)

    def log_message(self, format, *args):
        return


if __name__ == "__main__":
    host = os.environ.get("CYBERGUARD_HOST", "127.0.0.1")
    try:
        port = int(os.environ.get("CYBERGUARD_PORT", "8000"))
    except ValueError as error:
        raise SystemExit("CYBERGUARD_PORT must be an integer between 1 and 65535") from error

    if not 1 <= port <= 65535:
        raise SystemExit("CYBERGUARD_PORT must be an integer between 1 and 65535")

    server = ThreadingHTTPServer((host, port), CyberGuardHandler)
    print(
        f"Serving CyberGuard on {host}:{port} "
        f"(open http://localhost:{port}/ in this machine's browser)"
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping server...")
    finally:
        server.server_close()
