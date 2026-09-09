// Anthropic TypeScript SDK through witness: change one line.
//
//   witness serve --port 8787 --upstream https://api.anthropic.com --cache

import Anthropic from "@anthropic-ai/sdk";

const client = new Anthropic({
  baseURL: "http://127.0.0.1:8787", // <- the one changed line
});

const message = await client.messages.create({
  model: "claude-sonnet-5",
  max_tokens: 1024,
  temperature: 0,
  messages: [{ role: "user", content: "Prove that sqrt(2) is irrational." }],
});
console.log(message.content);
