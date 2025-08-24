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


def setup_logging(debug):
    """Configure logging for both console and file."""
    log_level = logging.DEBUG if debug else logging.INFO
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    logfile = f"server_log_{timestamp}.log"

    # Configure root logger
    logging.basicConfig(
        level=log_level,
        format="[%(asctime)s] [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
        handlers=[
            logging.FileHandler(logfile, mode="w", encoding="utf-8"),
            logging.StreamHandler(sys.stdout),  # Only shows info/debug if debug=True
        ],
    )

    logging.info(f"Logging to {logfile}")


def print_with_prompt(msg):
    """Print incoming messages while keeping the input prompt visible."""
    sys.stdout.write("\r" + msg + "\nYou: ")
    sys.stdout.flush()


def handle_receive(conn, server_socket):
    """Continuously receive JSON messages from the client."""
    while not shutdown_flag.is_set():
        try:
            data = conn.recv(1024)
            if not data:
                print_with_prompt("Client disconnected.")
                shutdown_flag.set()
                break

            message = json.loads(data.decode())
            logging.debug(f"RECEIVED JSON:\n{json.dumps(message, indent=2)}")
            msg_id = message.get("message-id", "N/A")
            timestamp = message.get("timestamp", "N/A")
            print_with_prompt(
                f"[Client] {message['message']} (id: {msg_id}, time: {timestamp})"
            )

        except (KeyboardInterrupt, EOFError):
            logging.info("Disconnecting client...")
            shutdown(conn, server_socket)
            sys.exit(0)
        except (json.JSONDecodeError, ConnectionResetError):
            print_with_prompt("Connection closed or invalid message.")
            shutdown_flag.set()
            break
        except OSError:
            break


def handle_send(conn, server_socket):
    """Continuously send JSON messages to the client."""
    while not shutdown_flag.is_set():
        try:
            msg = input("You: ")
            data = {
                "message": msg,
                "message-id": str(uuid.uuid4()),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
            conn.sendall(json.dumps(data).encode())
            logging.debug(f"SENT JSON:\n{json.dumps(data, indent=2)}")
        except (KeyboardInterrupt, EOFError):
            logging.info("Disconnecting client...")
            shutdown(conn, server_socket)
            sys.exit(0)
        except BrokenPipeError:
            print("\nClient connection lost.")
            shutdown_flag.set()
            break
        except OSError:
            break


def shutdown(conn, server_socket):
    """Gracefully shutdown server & sockets."""
    shutdown_flag.set()
    try:
        conn.shutdown(socket.SHUT_RDWR)
        conn.close()
    except Exception as e:
        logging.error(f"Error shutting down client connection: {e}")
    try:
        server_socket.shutdown(socket.SHUT_RDWR)
        server_socket.close()
    except Exception as e:
        logging.error(f"Error shutting down server socket: {e}")


def start_server(debug):
    """Start the JSON chat server."""
    setup_logging(debug)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((HOST, PORT))
        server_socket.listen()
        logging.info(f"Server listening on {HOST}:{PORT}")

        conn, addr = server_socket.accept()
        logging.info(f"Connected by {addr}")

        recv_thread = threading.Thread(
            target=handle_receive, args=(conn, server_socket), daemon=True
        )
        send_thread = threading.Thread(
            target=handle_send, args=(conn, server_socket), daemon=True
        )
        recv_thread.start()
        send_thread.start()

        try:
            while not shutdown_flag.is_set():
                recv_thread.join(0.2)
                send_thread.join(0.2)
        except KeyboardInterrupt:
            logging.info("Shutting down server...")
            shutdown(conn, server_socket)
            sys.exit(0)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="JSON Chat Server")
    parser.add_argument(
        "--debug", action="store_true", help="Enable debug logging and JSON output"
    )
    args = parser.parse_args()

    start_server(args.debug)
