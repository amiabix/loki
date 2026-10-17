"""Byte-level TCP/Unix proxy with a fixed one-way delay and an HTTP request log.

    hosted_flow_proxy.py LISTEN TARGET NAME RTT_MS LOG

LISTEN and TARGET are `tcp:HOST:PORT` or `unix:PATH`. Each direction is delayed by
RTT/2 and every new connection costs one extra RTT, like a TCP handshake. With a LOG
path, every connection and every HTTP request line (path segments of 20+ characters
shortened to `<id>`) is appended as one JSON line. Bodies and headers are never logged.

The hosted app flow runs relays in their own network namespace and reaches them
through a Unix socket, so relays keep listening on the exact loopback endpoint in
their manifest while this proxy, in the host namespace, adds the latency.
"""
import asyncio
import json
import re
import sys
import time

REQUEST = re.compile(rb"(GET|PUT|POST|DELETE|HEAD) (/[^ ?]*)")


async def connect(spec):
    kind, _, rest = spec.partition(":")
    if kind == "unix":
        return await asyncio.open_unix_connection(rest)
    host, port = rest.rsplit(":", 1)
    return await asyncio.open_connection(host, int(port))


async def serve(spec, handle):
    kind, _, rest = spec.partition(":")
    if kind == "unix":
        return await asyncio.start_unix_server(handle, rest)
    host, port = rest.rsplit(":", 1)
    return await asyncio.start_server(handle, host, int(port))


def short(path):
    return "/".join(part if len(part) < 20 else "<id>" for part in path.split("/"))


async def pipe(reader, writer, delay, log=None, name=None, connection=None):
    queue = asyncio.Queue()

    async def sender():
        while True:
            due, data = await queue.get()
            if data is None:
                break
            wait = due - time.monotonic()
            if wait > 0:
                await asyncio.sleep(wait)
            writer.write(data)
            await writer.drain()
        try:
            writer.close()
        except Exception:
            pass
    task = asyncio.create_task(sender())
    try:
        while True:
            data = await reader.read(65536)
            if not data:
                break
            if log is not None:
                for match in REQUEST.finditer(data):
                    log.write(json.dumps({"t": time.time(), "svc": name, "conn": connection,
                                          "m": match.group(1).decode(),
                                          "p": short(match.group(2).decode(errors="replace"))}) + "\n")
                log.flush()
            queue.put_nowait((time.monotonic() + delay, data))
    except Exception:
        pass
    queue.put_nowait((0, None))
    await task


async def main(listen, target, name, rtt_ms, log_path):
    delay = float(rtt_ms) / 2000.0
    log = open(log_path, "a") if log_path != "-" else None
    count = 0

    async def handle(client_reader, client_writer):
        nonlocal count
        count += 1
        connection = count
        if log is not None:
            log.write(json.dumps({"t": time.time(), "svc": name, "conn": connection, "m": "CONNECT"}) + "\n")
            log.flush()
        await asyncio.sleep(delay * 2)
        try:
            server_reader, server_writer = await connect(target)
        except OSError:
            client_writer.close()
            return
        await asyncio.gather(pipe(client_reader, server_writer, delay, log, name, connection),
                             pipe(server_reader, client_writer, delay))
    server = await serve(listen, handle)
    print("ready", flush=True)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main(*sys.argv[1:6]))
