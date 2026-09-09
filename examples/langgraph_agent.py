# LangGraph / LangChain through witness: same one-line change, on the
# chat-model constructor. Every node's model calls get recorded, cached,
# and attributed — no changes to the graph itself.
#
#   witness serve --port 8787 --upstream https://api.anthropic.com --cache

from langchain_anthropic import ChatAnthropic
from langgraph.prebuilt import create_react_agent

model = ChatAnthropic(
    model="claude-sonnet-5",
    temperature=0,
    anthropic_api_url="http://127.0.0.1:8787",  # <- the one changed line
)

agent = create_react_agent(model, tools=[])
result = agent.invoke({"messages": [("user", "Summarize the Collatz conjecture.")]})
print(result["messages"][-1].content)

# Re-run the whole graph later with ZERO model calls:
#   witness replay --port 8787
