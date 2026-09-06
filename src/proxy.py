import socket
import threading
import select
import sys
import re
from typing import List, Optional


def is_host_allowed(host: str, whitelist: List[str]) -> bool:
    """
    Checks whether a target host/domain is permitted by the whitelist.
    Supports exact matching and wildcard patterns (e.g. *.pypi.org, *.pythonhosted.org).
    """
    if not whitelist:
        return False

    # Normalize host: strip port if present and convert to lowercase
    clean_host = host.split(":")[0].strip().lower()

    for pattern in whitelist:
        pat = pattern.strip().lower()
        if pat == "*":
            return True
        if pat.startswith("*."):
            suffix = pat[1:]  # e.g. .pypi.org
            domain = pat[2:]  # e.g. pypi.org
            if clean_host.endswith(suffix) or clean_host == domain:
                return True
        elif clean_host == pat:
            return True

    return False


class FilteringForwardProxy:
    """
    A lightweight, zero-dependency HTTP/HTTPS forward filtering proxy.
    Intercepts CONNECT requests (HTTPS tunnels) and plain HTTP requests,
    enforcing domain whitelist rules to protect against outbound data exfiltration.
    """

    def __init__(self, whitelist: Optional[List[str]] = None, host: str = "0.0.0.0", port: int = 0):
        self.whitelist = whitelist or []
        self.host = host
        self.requested_port = port
        self.port = 0
        self.server_socket: Optional[socket.socket] = None
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._active_sockets = set()
        self._lock = threading.Lock()

    def start(self):
        """Binds to socket and starts the listener loop in a daemon thread."""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.requested_port))
        self.server_socket.listen(64)
        self.port = self.server_socket.getsockname()[1]
        self._running = True

        self._thread = threading.Thread(target=self._listen_loop, daemon=True, name="AgentShieldProxyThread")
        self._thread.start()

    def stop(self):
        """Stops the proxy listener and closes all active sockets."""
        self._running = False
        if self.server_socket:
            try:
                self.server_socket.close()
            except Exception:
                pass
            self.server_socket = None

        with self._lock:
            for s in list(self._active_sockets):
                try:
                    s.close()
                except Exception:
                    pass
            self._active_sockets.clear()

        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop()

    def _listen_loop(self):
        while self._running:
            try:
                if not self.server_socket:
                    break
                r, _, _ = select.select([self.server_socket], [], [], 0.5)
                if not r:
                    continue
                client_sock, client_addr = self.server_socket.accept()
                with self._lock:
                    self._active_sockets.add(client_sock)
                t = threading.Thread(target=self._handle_client, args=(client_sock,), daemon=True)
                t.start()
            except Exception:
                if not self._running:
                    break

    def _handle_client(self, client_sock: socket.socket):
        try:
            client_sock.settimeout(10.0)
            initial_data = b""
            while b"\r\n\r\n" not in initial_data and b"\n\n" not in initial_data:
                chunk = client_sock.recv(4096)
                if not chunk:
                    break
                initial_data += chunk
                if len(initial_data) > 65536:
                    break

            if not initial_data:
                return

            header_text = initial_data.decode("latin1", errors="ignore")
            lines = header_text.splitlines()
            if not lines:
                return

            request_line = lines[0]
            parts = request_line.split()
            if len(parts) < 2:
                return

            method = parts[0].upper()
            target = parts[1]

            if method == "CONNECT":
                # HTTPS Tunnel: CONNECT host:port HTTP/1.1
                host_port = target
                if ":" in host_port:
                    target_host, target_port_str = host_port.split(":", 1)
                    try:
                        target_port = int(target_port_str)
                    except ValueError:
                        target_port = 443
                else:
                    target_host = host_port
                    target_port = 443

                if not is_host_allowed(target_host, self.whitelist):
                    # Blocked domain
                    resp = (
                        b"HTTP/1.1 403 Forbidden\r\n"
                        b"Content-Type: text/plain\r\n"
                        b"Connection: close\r\n\r\n"
                        b"[AgentShield] Domain not whitelisted: " + target_host.encode() + b"\n"
                    )
                    client_sock.sendall(resp)
                    return

                # Allowed domain: establish outbound connection
                try:
                    remote_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    remote_sock.settimeout(10.0)
                    remote_sock.connect((target_host, target_port))
                    with self._lock:
                        self._active_sockets.add(remote_sock)
                except Exception as e:
                    err_resp = b"HTTP/1.1 502 Bad Gateway\r\n\r\n" + str(e).encode()
                    client_sock.sendall(err_resp)
                    return

                # Confirm tunnel establishment
                client_sock.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")

                # Duplex stream relay
                self._tunnel_duplex(client_sock, remote_sock)

            else:
                # Plain HTTP forwarding: GET http://host:port/path HTTP/1.1
                # Extract target host from URI or Host header
                target_host = None
                target_port = 80

                if target.startswith("http://"):
                    no_scheme = target[7:]
                    target_host_part = no_scheme.split("/")[0]
                    if ":" in target_host_part:
                        target_host, p = target_host_part.split(":", 1)
                        target_port = int(p)
                    else:
                        target_host = target_host_part
                else:
                    for line in lines[1:]:
                        if line.lower().startswith("host:"):
                            h = line.split(":", 1)[1].strip()
                            if ":" in h:
                                target_host, p = h.split(":", 1)
                                target_port = int(p)
                            else:
                                target_host = h
                            break

                if not target_host or not is_host_allowed(target_host, self.whitelist):
                    resp = (
                        b"HTTP/1.1 403 Forbidden\r\n"
                        b"Content-Type: text/plain\r\n"
                        b"Connection: close\r\n\r\n"
                        b"[AgentShield] Domain not whitelisted: " + (target_host or "unknown").encode() + b"\n"
                    )
                    client_sock.sendall(resp)
                    return

                try:
                    remote_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    remote_sock.settimeout(10.0)
                    remote_sock.connect((target_host, target_port))
                    with self._lock:
                        self._active_sockets.add(remote_sock)
                except Exception as e:
                    err_resp = b"HTTP/1.1 502 Bad Gateway\r\n\r\n" + str(e).encode()
                    client_sock.sendall(err_resp)
                    return

                # Send initial request data
                remote_sock.sendall(initial_data)
                self._tunnel_duplex(client_sock, remote_sock)

        except Exception:
            pass
        finally:
            try:
                client_sock.close()
            except Exception:
                pass
            with self._lock:
                self._active_sockets.discard(client_sock)

    def _tunnel_duplex(self, sock1: socket.socket, sock2: socket.socket):
        """Relays raw TCP packets bidirectionally between two sockets until one closes."""
        sockets = [sock1, sock2]
        sock1.setblocking(False)
        sock2.setblocking(False)

        while self._running:
            try:
                r, _, x = select.select(sockets, [], sockets, 1.0)
                if x:
                    break
                if not r:
                    continue

                for s in r:
                    other = sock2 if s is sock1 else sock1
                    data = s.recv(16384)
                    if not data:
                        return
                    other.sendall(data)
            except Exception:
                break
        try:
            sock1.close()
        except Exception:
            pass
        try:
            sock2.close()
        except Exception:
            pass
        with self._lock:
            self._active_sockets.discard(sock1)
            self._active_sockets.discard(sock2)
