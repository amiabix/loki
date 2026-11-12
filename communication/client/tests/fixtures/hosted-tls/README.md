# Owned TLS test fixtures

These public fixtures are exclusively for loopback tests. The server private key is a test key with no production authority. The CA private key was discarded. The leaf permits only `localhost`, and is signed by the included test CA. Both certificates expire in October 2036.

Unit tests add this CA only to a private test client built with the same request policy as production. Production uses the platform certificate verifier and never imports this CA. Tests also exercise production rejection of this untrusted chain, a hostname mismatch, redirects and signed challenge endpoint substitution.
