#!/usr/bin/env bash
set -euo pipefail

origin=${ORIGIN:?set ORIGIN to the wallet page origin, e.g. https://wallet.example}
front=${FRONT:-localhost}
upstream=${UPSTREAM:-127.0.0.1:2744}
loopback='^(http://)?(127\.0\.0\.1|\[::1\]):[0-9]{1,5}$'
socket='^unix//[a-zA-Z0-9_./-]+$'
https='^https://([a-zA-Z0-9.-]+|\[[a-fA-F0-9:]+\])(:[0-9]{1,5})?$'
if ! [[ $upstream =~ $loopback || $upstream =~ $socket || $upstream =~ $https ]]; then
  echo 'UPSTREAM must be a literal loopback IP:port, unix//path, or https://host[:port] (certificate verified)' >&2
  exit 2
fi
if [[ $front == localhost ]]; then
  listen=${LISTEN:-8443}
  bind='bind 127.0.0.1 [::1]'
  redirect='auto_https disable_redirects'
else
  listen=${LISTEN:-443}
  bind=
  redirect=
fi
command -v caddy >/dev/null || { echo "caddy not found on PATH" >&2; exit 1; }

conf=$(mktemp -t frostd-caddy.XXXXXX)
trap 'rm -f "$conf"' EXIT
cat > "$conf" <<EOF
{
	admin off
	${redirect}
}

https://${front}:${listen} {
	${bind}
	# CORS: only the one wallet origin, and answer the preflight ourselves so frostd
	# (which emits no CORS headers) never sees the OPTIONS.
	@preflight method OPTIONS
	handle @preflight {
		header Access-Control-Allow-Origin "${origin}"
		header Access-Control-Allow-Methods "POST, OPTIONS"
		header Access-Control-Allow-Headers "authorization, content-type"
		header Access-Control-Max-Age "600"
		respond 204
	}
	handle {
		header Access-Control-Allow-Origin "${origin}"
		header Vary "Origin"
		reverse_proxy ${upstream}
	}
}
EOF

echo "frostd TLS front: https://${front}:${listen}  ->  ${upstream}   (CORS origin: ${origin})"
echo "point the wasm signer at:  https://${front}:${listen}"
caddy run --config "$conf" --adapter caddyfile &
pid=$!
stop() {
  kill -TERM "$pid" 2>/dev/null || true
  wait "$pid" || true
  exit "$1"
}
trap 'stop 130' INT
trap 'stop 143' TERM
wait "$pid"
