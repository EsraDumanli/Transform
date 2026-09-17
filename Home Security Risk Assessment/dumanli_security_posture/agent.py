import os

from google.adk.agents.llm_agent import Agent
from google.adk.models.lite_llm import LiteLlm

from .tools import network_tools, risk_score_tools, system_tools, topology_tools, vuln_tools

# A bare model id (e.g. "gemini-3.5-flash") calls Gemini directly. A
# "provider/model" id (e.g. "anthropic/claude-sonnet-5") routes through
# LiteLLM to that provider instead, reading its own API key from the
# environment (ANTHROPIC_API_KEY for Anthropic, OPENAI_API_KEY for OpenAI,
# etc.) rather than GOOGLE_API_KEY.
_model_id = os.getenv("DUMANLI_MODEL", "anthropic/claude-sonnet-5")
MODEL = LiteLlm(model=_model_id) if "/" in _model_id else _model_id

device_scanner_agent = Agent(
    model=MODEL,
    name="device_scanner_agent",
    description="Inventories this Mac: OS patch level, installed packages, open ports, firewall/FileVault/SIP state.",
    instruction=(
        "You audit the local device only. Call get_os_info, get_pending_os_updates, "
        "list_installed_packages, list_listening_ports, get_firewall_status, "
        "get_filevault_status, and get_sip_status. Summarize findings as a list of "
        "facts (software + version, listening ports + process, security toggles), "
        "flagging anything outdated, exposed, or disabled. Do not speculate about "
        "CVEs yourself — that is another agent's job."
    ),
    tools=[
        system_tools.get_os_info,
        system_tools.get_pending_os_updates,
        system_tools.list_installed_packages,
        system_tools.list_listening_ports,
        system_tools.get_firewall_status,
        system_tools.get_filevault_status,
        system_tools.get_sip_status,
    ],
)

network_recon_agent = Agent(
    model=MODEL,
    name="network_recon_agent",
    description="Discovers devices on the local LAN and fingerprints their open services, including the router.",
    instruction=(
        "You audit the local network only, never anything outside a private "
        "subnet. First call get_local_subnet, then discover_lan_hosts on that "
        "CIDR. Then call get_default_gateway to identify the router. For the "
        "router and any other interesting host, call scan_host_services, and "
        "for web-exposed hosts (ports 80/443/8080/8443) call fetch_http_banner "
        "to identify make/model/firmware. Never attempt to log into anything. "
        "Report each host with its IP, vendor guess, and open service/version list."
    ),
    tools=[
        network_tools.get_default_gateway,
        network_tools.get_local_subnet,
        network_tools.discover_lan_hosts,
        network_tools.scan_host_services,
        network_tools.fetch_http_banner,
    ],
)

vulnerability_analyst_agent = Agent(
    model=MODEL,
    name="vulnerability_analyst_agent",
    description="Cross-references discovered software/firmware versions against the public NVD CVE database.",
    instruction=(
        "Given a list of products/services and their versions (from the device "
        "or network agents), call lookup_cves_for_product for each one. "
        "Summarize matched CVEs with id, severity, and a one-line description. "
        "Note when a version is too vague to match confidently."
    ),
    tools=[vuln_tools.lookup_cves_for_product],
)

patch_planner_agent = Agent(
    model=MODEL,
    name="patch_planner_agent",
    description="Turns raw findings and CVEs into a prioritized, concrete remediation plan.",
    instruction=(
        "You take findings gathered by the other agents (device inventory, "
        "network/router recon, CVE matches) and produce a prioritized patch "
        "plan: Critical / High / Medium / Low. For each item give: what's "
        "wrong, why it matters, and the exact remediation step (e.g. 'brew "
        "upgrade <pkg>', 'softwareupdate -i -a', 'log into router at "
        "http://<gateway> and update firmware / disable UPnP / change default "
        "admin password / disable remote management'). You do not run any "
        "tools yourself — you only synthesize a plan from what you're given."
    ),
    tools=[],
)

risk_score_agent = Agent(
    model=MODEL,
    name="risk_score_agent",
    description="Scores the environment's overall risk 0-100 from findings the other agents already gathered.",
    instruction=(
        "You do not scan anything yourself. Take the findings already gathered "
        "by device_scanner_agent, network_recon_agent, and "
        "vulnerability_analyst_agent in this conversation, and translate each "
        "one into a finding dict: {title, area: device|router|lan|other, "
        "severity: critical|high|medium|low|info, status: fail|pass|unknown}. "
        "Use status 'fail' for a confirmed gap, 'pass' for a confirmed "
        "protective control (e.g. FileVault on, no telnet exposed), and "
        "'unknown' for anything checked but not confirmed either way — never "
        "guess a fail or pass you don't have evidence for. Include every "
        "finding you have, not just the bad ones, then call compute_risk_score "
        "with the full list. Report the resulting score and label, then "
        "explain the top 2-3 contributors to exposure and the hygiene credit "
        "applied, in plain language. If you don't yet have any findings, say "
        "so and suggest running the other agents first."
    ),
    tools=[risk_score_tools.compute_risk_score],
)

topology_mapper_agent = Agent(
    model=MODEL,
    name="topology_mapper_agent",
    description="Maps this application's own agents, their skills, and their tools as a topology diagram.",
    instruction=(
        "Call describe_agent_topology and present both a short prose summary "
        "(which agents exist, what each is responsible for, which tools/skills "
        "each has) and the returned Mermaid diagram verbatim in a mermaid code "
        "block so it can be rendered."
    ),
    tools=[topology_tools.describe_agent_topology],
)

root_agent = Agent(
    model=MODEL,
    name="dumanli_security_posture",
    description="Orchestrates a full home security posture assessment: this device, the LAN, the router, and a patch plan.",
    instruction=(
        "You are a home network security posture assistant for the user's own "
        "device and LAN — defensive/informational only, never offensive. "
        "For a full assessment: delegate to device_scanner_agent for this "
        "machine, then network_recon_agent for the LAN and router, then give "
        "the discovered product/version list to vulnerability_analyst_agent, "
        "then hand everything to risk_score_agent for a single risk score, "
        "then to patch_planner_agent for a prioritized remediation plan. If "
        "the user only asks 'what's my risk score' or similar, and findings "
        "already exist earlier in the conversation, delegate straight to "
        "risk_score_agent rather than re-running every scan. If the user "
        "just asks about your own architecture ('what agents do you have', "
        "'show your topology'), delegate to topology_mapper_agent instead. "
        "Always state clearly that all scanning stays within the user's own "
        "device and private LAN."
    ),
    sub_agents=[
        device_scanner_agent,
        network_recon_agent,
        vulnerability_analyst_agent,
        risk_score_agent,
        patch_planner_agent,
        topology_mapper_agent,
    ],
)
