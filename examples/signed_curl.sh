#!/usr/bin/env bash
# Full Pact identity flow from the shell, using witness's own CLI as the
# signing client. For raw curl, sign METHOD\nPATH\nTIMESTAMP\nblake3(body)
# with your agent key and send the x-pact-* headers yourself.
set -euo pipefail

witness keygen --out keys/human
witness keygen --out keys/agent
witness delegate --issuer keys/human --subject keys/agent.pub \
  --cap "model:claude-*" --ttl-secs 3600 --out chain.json

# Signed, delegated, capability-checked call through the proxy:
witness call --key keys/agent --chain chain.json \
  --model claude-sonnet-5 --text "hello from a signed agent"

# The proxy will refuse this one — the grant only covers claude models:
witness call --key keys/agent --chain chain.json \
  --model gpt-6-astra --text "should be denied" || echo "denied, as designed"
