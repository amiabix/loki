#!/usr/bin/env bash
# Put lightwalletd behind gRPC-web + CORS so the in-browser (wasm) signer can scan the chain.
#
# WHY: lightwalletd speaks gRPC over HTTP/2 (trailers, no CORS). A browser can't make native
# gRPC calls at all, and testnet.zec.rocks answers a CORS preflight with 404 and replies
# `application/grpc`. Envoy's grpc_web filter translates gRPC-web (HTTP/1.1 or 2, trailers in
# the body) to gRPC for the upstream, and its CORS filter answers the preflight for ONE origin,
# the signer origin (not the wallet: the scan runs on the signer page). Like frostd-tls.sh for
# frostd, this is the deploy piece; nothing in lightwalletd changes.
#
# Usage:
#   ORIGIN=http://localhost:3002 ./lightwalletd-grpcweb.sh
#   ORIGIN=https://signer.example UPSTREAM=lightwalletd.example:443 LISTEN=127.0.0.1:9068 ./lightwalletd-grpcweb.sh
#
# Env:
#   ORIGIN    the exact signer origin allowed to call it (REQUIRED, no trailing slash)
#   UPSTREAM  lightwalletd host:port, reached over TLS     (default: testnet.zec.rocks:443)
#   LISTEN    address:port Envoy binds, plaintext          (default: 127.0.0.1:9068)
# ponytail: plaintext listener, fine for a loopback dev signer; a public https signer origin
# needs this behind TLS (Caddy or cloudflared, as frostd-tls.sh does).
# Requires: docker (pulls envoyproxy/envoy:v1.31.2).
set -euo pipefail

origin=${ORIGIN:?set ORIGIN to the signer page origin, e.g. http://localhost:3002}
upstream=${UPSTREAM:-testnet.zec.rocks:443}
listen=${LISTEN:-127.0.0.1:9068}
host=${upstream%:*}; port=${upstream##*:}
command -v docker >/dev/null || { echo "docker not found on PATH" >&2; exit 1; }

conf=$(mktemp -t lightwalletd-envoy.XXXXXX.yaml)
trap 'rm -f "$conf"' EXIT
chmod 644 "$conf" # read by the container's envoy user; holds no secret
cat > "$conf" <<YAML
static_resources:
  listeners:
  - name: grpc_web
    address: { socket_address: { address: "${listen%:*}", port_value: ${listen##*:} } }
    filter_chains:
    - filters:
      - name: envoy.filters.network.http_connection_manager
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
          stat_prefix: lightwalletd
          route_config:
            virtual_hosts:
            - name: lightwalletd
              domains: ["*"]
              typed_per_filter_config:
                envoy.filters.http.cors:
                  "@type": type.googleapis.com/envoy.extensions.filters.http.cors.v3.CorsPolicy
                  allow_origin_string_match: [{ exact: "${origin}" }]
                  allow_methods: "POST, OPTIONS"
                  allow_headers: "content-type, x-grpc-web, x-user-agent, grpc-timeout"
                  expose_headers: "grpc-status, grpc-message"
                  max_age: "600"
              routes:
              # Only the wallet RPC service; nothing else on the upstream is reachable.
              - match: { prefix: "/cash.z.wallet.sdk.rpc.CompactTxStreamer/" }
                route: { cluster: lightwalletd, timeout: 0s }
          http_filters:
          - name: envoy.filters.http.grpc_web
            typed_config: { "@type": type.googleapis.com/envoy.extensions.filters.http.grpc_web.v3.GrpcWeb }
          - name: envoy.filters.http.cors
            typed_config: { "@type": type.googleapis.com/envoy.extensions.filters.http.cors.v3.Cors }
          - name: envoy.filters.http.router
            typed_config: { "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router }
  clusters:
  - name: lightwalletd
    type: LOGICAL_DNS
    dns_lookup_family: V4_ONLY
    typed_extension_protocol_options:
      envoy.extensions.upstreams.http.v3.HttpProtocolOptions:
        "@type": type.googleapis.com/envoy.extensions.upstreams.http.v3.HttpProtocolOptions
        explicit_http_config: { http2_protocol_options: {} }
    load_assignment:
      cluster_name: lightwalletd
      endpoints: [{ lb_endpoints: [{ endpoint: { address: { socket_address: { address: "${host}", port_value: ${port} } } } }] }]
    transport_socket:
      name: envoy.transport_sockets.tls
      typed_config:
        "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext
        sni: "${host}"
        common_tls_context:
          validation_context:
            trusted_ca: { filename: /etc/ssl/certs/ca-certificates.crt }
            match_typed_subject_alt_names: [{ san_type: DNS, matcher: { exact: "${host}" } }]
YAML

echo "lightwalletd gRPC-web front: http://${listen}  ->  https://${upstream}   (CORS origin: ${origin})"
# --base-id: Envoys on one host network share a domain-socket namespace; one per listen port.
exec docker run --rm --network host -v "$conf:/etc/envoy/envoy.yaml:ro" envoyproxy/envoy:v1.31.2 -c /etc/envoy/envoy.yaml --log-level warn --base-id "${listen##*:}"
