import argparse
import json
import logging
import socket
import sys
import threading
import uuid
from datetime import datetime, timezone

HOST = "127.0.0.1"
PORT = 5000
shutdown_flag = threading.Event()


def setup_logging(debug: bool = False):
    """Configure logging for both console and file."""
    log_level = logging.DEBUG if debug else logging.INFO
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    logfile = f"client_log_{timestamp}.log"

    logging.basicConfig(
        level=log_level,
        format="[%(asctime)s] [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
        handlers=[
            logging.FileHandler(logfile, mode="w", encoding="utf-8"),
            logging.StreamHandler(sys.stdout),
        ],
    )

    logging.info(f"Logging to {logfile}")


def print_with_prompt(msg: str):
    """Print incoming messages while keeping the input prompt visible."""
    sys.stdout.write("\r" + msg + "\nYou: ")
    sys.stdout.flush()


def handle_receive(sock: socket.socket):
    """Continuously receive JSON messages from the server."""
    while not shutdown_flag.is_set():
        try:
            data = sock.recv(1024)
            if not data:
                print_with_prompt("Server disconnected.")
                shutdown_flag.set()
                break

            message = json.loads(data.decode())
            logging.debug(f"RECEIVED JSON:\n{json.dumps(message, indent=2)}")
            msg_id = message.get("message-id", "N/A")
            timestamp = message.get("timestamp", "N/A")
            print_with_prompt(
                f"[Server] {message['message']} (id: {msg_id}, time: {timestamp})"
            )

        except (json.JSONDecodeError, ConnectionResetError):
            print_with_prompt("Connection closed or invalid message.")
            shutdown_flag.set()
            break
        except OSError:
            break


def handle_send(sock: socket.socket):
    """Continuously send JSON messages to the server."""
    while not shutdown_flag.is_set():
        try:
            msg = input("You: ")
            data = {
                "message": msg,
                "message-id": str(uuid.uuid4()),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
            sock.sendall(json.dumps(data).encode())
            logging.debug(f"SENT JSON:\n{json.dumps(data, indent=2)}")
        except BrokenPipeError:
            print("\nServer connection lost.")
            shutdown_flag.set()
            break
        except OSError:
            break


def shutdown(sock: socket.socket):
    """Gracefully shutdown client & socket."""
    shutdown_flag.set()
    try:
        sock.shutdown(socket.SHUT_RDWR)
        sock.close()
    except Exception:
        pass


def start_client(debug: bool = False):
    """Start the JSON chat client."""
    setup_logging(debug)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.connect((HOST, PORT))
        logging.info(f"Connected to server at {HOST}:{PORT}")

        recv_thread = threading.Thread(
            target=handle_receive, args=(client_socket,), daemon=True
        )
        send_thread = threading.Thread(
            target=handle_send, args=(client_socket,), daemon=True
        )
        recv_thread.start()
        send_thread.start()

        try:
            while not shutdown_flag.is_set():
                recv_thread.join(0.2)
                send_thread.join(0.2)
        except KeyboardInterrupt:
            logging.info("Disconnecting client...")
            shutdown(client_socket)
            sys.exit(0)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="JSON Chat Client")
    parser.add_argument(
        "--debug", action="store_true", help="Enable debug logging and JSON output"
    )
    args = parser.parse_args()

    start_client(debug=args.debug)
