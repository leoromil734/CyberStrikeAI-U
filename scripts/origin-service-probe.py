#!/usr/bin/env python3
"""Read a service banner through a local HTTP CONNECT proxy, then optionally try one SSH password.

Direct sockets to an origin often time out from this host. Ad-hoc tunnels that
wait only a few seconds report "no banner" before the proxy finishes connecting.
This waits up to 45 seconds and prints a single status line:

  connect_refused | banner_timeout | banner_ok | auth_failed | auth_ok
"""

import argparse
import socket
import sys


def connect_via_proxy(proxy_host, proxy_port, host, port, timeout):
    sock = socket.create_connection((proxy_host, proxy_port), timeout)
    sock.settimeout(timeout)
    request = (
        f"CONNECT {host}:{port} HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        "Proxy-Connection: keep-alive\r\n\r\n"
    ).encode()
    sock.sendall(request)
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            raise SystemExit("connect_closed")
        buf += chunk
        if len(buf) > 8192:
            raise SystemExit("connect_refused")
    head = buf.split(b"\r\n", 1)[0].decode("latin1", "replace")
    if " 200 " not in head:
        print(head)
        raise SystemExit("connect_refused")
    return sock


def read_banner(sock):
    try:
        data = sock.recv(512)
    except socket.timeout:
        raise SystemExit("banner_timeout")
    if not data:
        raise SystemExit("banner_timeout")
    return data


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--proxy", help="host:port of the local HTTP proxy")
    parser.add_argument("--timeout", type=int, default=45)
    parser.add_argument("--ssh-user")
    parser.add_argument("--ssh-password")
    args = parser.parse_args()

    if args.proxy:
        proxy_host, proxy_port = args.proxy.rsplit(":", 1)
        sock = connect_via_proxy(proxy_host, int(proxy_port), args.host, args.port, args.timeout)
    else:
        sock = socket.create_connection((args.host, args.port), args.timeout)
        sock.settimeout(args.timeout)

    banner = read_banner(sock)
    text = banner.decode("latin1", "replace").replace("\n", " ").strip()
    print(f"banner_ok {text[:180]}")
    if args.port != 22 or not args.ssh_user:
        return
    try:
        import paramiko
    except ImportError:
        print("auth_skipped paramiko_missing")
        return
    try:
        transport = paramiko.Transport(sock)
        transport.banner_timeout = args.timeout
        transport.auth_timeout = args.timeout
        transport.start_client(timeout=args.timeout)
        transport.auth_password(args.ssh_user, args.ssh_password or "")
        print("auth_ok" if transport.is_authenticated() else "auth_failed")
        transport.close()
    except paramiko.AuthenticationException:
        print("auth_failed")
    except Exception as exc:
        print(f"auth_error {type(exc).__name__}")


if __name__ == "__main__":
    try:
        main()
    except socket.timeout:
        print("banner_timeout")
        sys.exit(1)
    except OSError as exc:
        print(f"connect_error {exc.errno or type(exc).__name__}")
        sys.exit(1)
