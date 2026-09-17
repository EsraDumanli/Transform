"""Self-introspection: map this app's own agents, their skills, and tools.

Walks the live agent tree (root_agent and its sub_agents) and reports each
agent's name, role, and the tools it can call — plus a Mermaid diagram of
the whole graph. The agent import is deferred to call time to avoid a
circular import with agent.py, which registers this module as a tool.
"""


def _tool_name(tool) -> str:
    return getattr(tool, "__name__", None) or getattr(tool, "name", None) or repr(tool)


def _tool_doc(tool) -> str:
    doc = getattr(tool, "__doc__", None) or getattr(tool, "description", None) or ""
    return doc.strip().splitlines()[0] if doc.strip() else ""


def _describe_agent(agent) -> dict:
    node = {
        "name": agent.name,
        "description": getattr(agent, "description", "") or "",
        "model": str(getattr(agent, "model", "")) or None,
        "tools": [
            {"name": _tool_name(t), "skill": _tool_doc(t)}
            for t in getattr(agent, "tools", [])
        ],
        "sub_agents": [],
    }
    for sub in getattr(agent, "sub_agents", []):
        node["sub_agents"].append(_describe_agent(sub))
    return node


def _to_mermaid(node: dict, lines: list[str]) -> None:
    safe_name = node["name"]
    for sub in node["sub_agents"]:
        lines.append(f'  {safe_name}["{safe_name}"] -->|delegates to| {sub["name"]}["{sub["name"]}"]')
        _to_mermaid(sub, lines)
    for tool in node["tools"]:
        tool_id = f'{safe_name}_{tool["name"]}'
        label = tool["name"].replace("_", " ")
        lines.append(f'  {safe_name} -.->|uses| {tool_id}(["{label}"])')


def describe_agent_topology() -> dict:
    """Return this application's own agent topology: agents, skills, tools.

    Introspects the live root_agent and every sub_agent recursively,
    reporting each agent's name/role/model and the tools (skills) it can
    invoke, plus a ready-to-render Mermaid flowchart of the whole graph.
    """
    from dumanli_security_posture.agent import root_agent

    tree = _describe_agent(root_agent)
    lines = ["flowchart TD"]
    _to_mermaid(tree, lines)
    return {"tree": tree, "mermaid": "\n".join(lines)}
