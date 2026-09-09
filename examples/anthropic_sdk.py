# Anthropic Python SDK through witness: change one line.
#
#   witness serve --port 8787 --upstream https://api.anthropic.com --cache
#
# Everything below is your existing code, except base_url.

import anthropic

client = anthropic.Anthropic(
    base_url="http://127.0.0.1:8787",  # <- the one changed line
)

message = client.messages.create(
    model="claude-sonnet-5",
    max_tokens=1024,
    temperature=0,  # deterministic -> witness may serve repeats from cache
    messages=[{"role": "user", "content": "Prove that sqrt(2) is irrational."}],
)
print(message.content[0].text)

# Every call is now in the hash-chained journal:
#   witness log
#   witness audit --contains "sqrt(2)"
