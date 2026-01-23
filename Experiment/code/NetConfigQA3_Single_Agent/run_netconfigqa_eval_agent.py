import os
import json
import logging
import time
import datetime
import argparse
import re
import ast
import ipaddress
from collections import defaultdict
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, asdict

# LangChain imports
try:
    from langchain_openai import ChatOpenAI
    from langchain.agents import AgentExecutor, create_react_agent
    from langchain_core.prompts import PromptTemplate
    from langchain_core.tools import Tool
    from langchain_community.callbacks.manager import get_openai_callback
except ImportError:
    print("Error: Required LangChain packages not found. Please run 'pip install -r requirements_agent.txt'")
    exit(1)

# vLLM/Token imports
try:
    import tiktoken
    VLLM_AVAILABLE = True
except ImportError:
    VLLM_AVAILABLE = False

# 로깅 설정
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s | %(levelname)s | %(message)s',
    handlers=[
        logging.FileHandler(f"logs/eval_agent_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("NetConfigQA_Agent")

# 토큰 계산기
try:
    _encoding = tiktoken.get_encoding("cl100k_base")
except:
    _encoding = None

def count_tokens(text: str) -> int:
    if _encoding and text:
        return len(_encoding.encode(text))
    return int(len(str(text or "")) / 4)

def _strip_final_answer_prefix(text: str) -> str:
    """
    Normalize common agent/model wrappers so we can parse structured outputs reliably.
    Examples:
      - "Final Answer: {...}" -> "{...}"
      - "final answer: [..]"  -> "[..]"
    """
    if text is None:
        return ""
    s = str(text).strip()
    # Remove common prefixes (case-insensitive)
    s = re.sub(r'^\s*final\s+answer\s*:\s*', '', s, flags=re.IGNORECASE)
    s = re.sub(r'^\s*answer\s*:\s*', '', s, flags=re.IGNORECASE)
    return s.strip()

def _normalize_prediction_by_type(pred: str, answer_type: str) -> str:
    """
    Convert model output into a canonical, JSON-friendly string for evaluation/storage.
    - map  -> JSON object string with double quotes
    - set  -> JSON array string with double quotes
    - number/numeric -> digits only (int) when possible
    - text -> stripped string
    """
    at = (answer_type or "text").strip().lower()
    s = _strip_final_answer_prefix(pred)

    if at in ("map", "json", "dictionary", "map_str_str"):
        # Try JSON first
        for candidate in (s, s.strip('`'), s.strip()):
            try:
                obj = json.loads(candidate)
                if isinstance(obj, dict):
                    # Canonicalize keys/values to strings for stable evaluation
                    canon = {str(k): ("" if v is None else str(v)) for k, v in obj.items()}
                    return json.dumps(canon, ensure_ascii=False, sort_keys=True)
            except Exception:
                pass
        # Fallback: Python literal dict (single quotes etc.)
        try:
            obj = ast.literal_eval(s)
            if isinstance(obj, dict):
                canon = {str(k): ("" if v is None else str(v)) for k, v in obj.items()}
                return json.dumps(canon, ensure_ascii=False, sort_keys=True)
        except Exception:
            pass
        return s  # last-resort: keep raw

    if at in ("set", "list", "set_str", "list_str"):
        # Try JSON array
        for candidate in (s, s.strip('`'), s.strip()):
            try:
                obj = json.loads(candidate)
                if isinstance(obj, list):
                    canon = ["" if v is None else str(v) for v in obj]
                    return json.dumps(canon, ensure_ascii=False)
            except Exception:
                pass
        # Fallback: Python literal list/tuple/set
        try:
            obj = ast.literal_eval(s)
            if isinstance(obj, (list, tuple, set)):
                canon = ["" if v is None else str(v) for v in list(obj)]
                return json.dumps(canon, ensure_ascii=False)
        except Exception:
            pass
        return s

    if at in ("numeric", "number", "scalar_int", "int", "integer"):
        m = re.search(r'-?\d+(\.\d+)?', s)
        if not m:
            return s
        num = m.group(0)
        # Prefer integer rendering for count-style answers
        try:
            f = float(num)
            if f.is_integer():
                return str(int(f))
            return str(f)
        except Exception:
            return num

    return s

@dataclass
class QueryMetrics:
    question_id: str
    total_time: float
    tool_calls: int
    tool_call_details: List[Dict[str, Any]]
    prompt_tokens: int
    completion_tokens: int
    total_tokens: int
    context_size: int
    agent_steps: int
    success: bool
    error_msg: Optional[str] = None

class FactsQueryEngine:
    def __init__(self, facts_data: Dict[str, Any]):
        self.facts = facts_data
        self.devices = {d['system']['hostname']: d for d in facts_data['devices']}
        self.query_count = 0
        self.cache = {}
        # Facts-only indices (for *information retrieval*, not path computation)
        self._indices_built = False
        self._ip_to_iface: Dict[str, Dict[str, Any]] = {}
        self._subnet_to_ifaces: Dict[str, List[Dict[str, Any]]] = defaultdict(list)

    def _build_indices(self) -> None:
        """Build IP/subnet indices for evidence lookup (no graph/path computation)."""
        if self._indices_built:
            return
        for dev_name, dev in self.devices.items():
            for iface in (dev.get("interfaces", []) or []):
                if not isinstance(iface, dict):
                    continue
                ipv4 = iface.get("ipv4")
                if not ipv4:
                    continue
                try:
                    iface_obj = ipaddress.ip_interface(str(ipv4))
                except Exception:
                    continue
                ip_str = str(iface_obj.ip)
                net_str = str(iface_obj.network)
                entry = {
                    "device": dev_name,
                    "interface": iface.get("name"),
                    "ipv4": ipv4,
                    "status": iface.get("status"),
                    "network": net_str,
                }
                self._ip_to_iface[ip_str] = entry
                self._subnet_to_ifaces[net_str].append(entry)
        self._indices_built = True

    def _resolve_device(self, name: str) -> Optional[str]:
        if not name:
            return None
        if name in self.devices:
            return name
        for d in self.devices:
            if d.lower() == str(name).lower():
                return d
        return None

    def query_device_info(self, device: str, field: str) -> Any:
        # #region agent log
        with open("/home/kilab_pyj/codespace/.cursor/debug.log", "a") as f:
            f.write(json.dumps({"location": "run_netconfigqa_eval_agent.py:72", "message": "query_device_info entry", "data": {"device": device, "field": field}, "timestamp": time.time() * 1000, "hypothesisId": "A"}) + "\n")
        # #endregion
        self.query_count += 1
        cache_key = f"device:{device}:{field}"
        if cache_key in self.cache: return self.cache[cache_key]
        
        target_device = None
        if device in self.devices:
            target_device = device
        else:
            for d_name in self.devices:
                if d_name.lower() == device.lower():
                    target_device = d_name
                    break
        
        if not target_device: 
            # #region agent log
            with open("/home/kilab_pyj/codespace/.cursor/debug.log", "a") as f:
                f.write(json.dumps({"location": "run_netconfigqa_eval_agent.py:85", "message": "device not found", "data": {"device": device}, "timestamp": time.time() * 1000, "hypothesisId": "A"}) + "\n")
            # #endregion
            return None
            
        dev = self.devices[target_device]
        
        field_map = {
            'hostname': lambda d: d['system'].get('hostname'),
            'version': lambda d: d['system'].get('version'),
            'os': lambda d: d['system'].get('version'),
            'software': lambda d: d['system'].get('version'),
            'vendor': lambda d: d.get('vendor'),
            'users': lambda d: d['system'].get('users'),
            'local_users': lambda d: d['system'].get('users'),
            'local_user_count': lambda d: len(d['system'].get('users', [])),
            'user_count': lambda d: len(d['system'].get('users', [])),
            'timezone': lambda d: d['system'].get('timezone') or d.get('timezone'),
            'domain_name': lambda d: d['system'].get('domain_name'),
            'interfaces': lambda d: d.get('interfaces'),
            'interface_count': lambda d: d.get('num_interfaces') or len(d.get('interfaces', [])),
            'bgp': lambda d: d.get('routing', {}).get('bgp'),
            'ospf': lambda d: d.get('routing', {}).get('ospf'),
            # Dataset metric names (text)
            'ssh_version_text': lambda d: d.get('security', {}).get('ssh', {}).get('version'),
            'vty_transport_input_text': lambda d: d.get('line', {}).get('vty', {}).get('transport_input'),
            'vty_login_mode_text': lambda d: d.get('line', {}).get('vty', {}).get('login_mode'),
            'aaa_authentication_method': lambda d: (
                "미설정"
                if not d.get('security', {}).get('aaa', {}).get('present', False)
                else (d.get('security', {}).get('aaa', {}).get('authentication') or "미설정")
            ),
            'static_routes': lambda d: d.get('configuration', {}).get('routing', {}).get('static_routes_count'),
            'static_route_count': lambda d: d.get('configuration', {}).get('routing', {}).get('static_routes_count'),
            'static_routes_count': lambda d: d.get('configuration', {}).get('routing', {}).get('static_routes_count'),
            'default_route_next_hops': lambda d: d.get('configuration', {}).get('routing', {}).get('default_route_next_hops'),
        }
        
        if field in field_map:
            res = field_map[field](dev)
            # #region agent log
            with open("/home/kilab_pyj/codespace/.cursor/debug.log", "a") as f:
                f.write(json.dumps({"location": "run_netconfigqa_eval_agent.py:110", "message": "field found in map", "data": {"field": field, "result": str(res)[:100]}, "timestamp": time.time() * 1000, "hypothesisId": "A"}) + "\n")
            # #endregion
            self.cache[cache_key] = res
            return res
            
        field_lower = field.lower()
        search_dicts = [
            dev.get('system', {}), 
            dev, 
            dev.get('routing', {}), 
            dev.get('security', {}),
            dev.get('configuration', {}),
            dev.get('configuration', {}).get('routing', {}),
            dev.get('configuration', {}).get('security', {})
        ]
        for sd in search_dicts:
            if isinstance(sd, dict):
                for k, v in sd.items():
                    if k.lower() == field_lower:
                        # #region agent log
                        with open("/home/kilab_pyj/codespace/.cursor/debug.log", "a") as f:
                            f.write(json.dumps({"location": "run_netconfigqa_eval_agent.py:126", "message": "field found in search_dicts", "data": {"field": field, "key": k, "result": str(v)[:100]}, "timestamp": time.time() * 1000, "hypothesisId": "A"}) + "\n")
                        # #endregion
                        self.cache[cache_key] = v
                        return v
        
        # #region agent log
        with open("/home/kilab_pyj/codespace/.cursor/debug.log", "a") as f:
            f.write(json.dumps({"location": "run_netconfigqa_eval_agent.py:130", "message": "field not found anywhere", "data": {"field": field}, "timestamp": time.time() * 1000, "hypothesisId": "A"}) + "\n")
        # #endregion
        return None

    def list_all_devices(self, field: str = None) -> List[Any]:
        self.query_count += 1
        if not field: return list(self.devices.keys())
        return [self.query_device_info(d, field) for d in self.devices]

    def interface_status_map(self, device: str) -> Dict[str, str]:
        """Return {interface_name: status} for a device (best for answer_type=map)."""
        self.query_count += 1
        if device not in self.devices:
            # try case-insensitive match
            for d_name in self.devices:
                if d_name.lower() == str(device).lower():
                    device = d_name
                    break
        dev = self.devices.get(device)
        if not dev:
            return {}
        res: Dict[str, str] = {}
        for iface in (dev.get('interfaces', []) or []):
            if not isinstance(iface, dict):
                continue
            name = iface.get('name')
            if not name:
                continue
            status = iface.get('status')
            if status is None:
                status = ""
            res[str(name)] = str(status)
        return res

    def ip_owner_evidence(self, ip: str) -> Any:
        """Return which device/interface owns an IP (evidence only)."""
        self.query_count += 1
        self._build_indices()
        try:
            ip_norm = str(ipaddress.ip_address(str(ip).strip()))
        except Exception:
            return None
        return self._ip_to_iface.get(ip_norm)

    def subnet_members_evidence(self, cidr_or_ip: str) -> List[Dict[str, Any]]:
        """
        Return all interfaces in the same subnet (evidence only).
        Input: CIDR (e.g., 172.16.1.0/24) or an IP (e.g., 172.16.1.2).
        """
        self.query_count += 1
        self._build_indices()
        s = str(cidr_or_ip).strip()
        net_str = None
        try:
            if "/" in s:
                net_str = str(ipaddress.ip_network(s, strict=False))
            else:
                # find exact owner subnet first
                ip_norm = str(ipaddress.ip_address(s))
                owner = self._ip_to_iface.get(ip_norm)
                if owner:
                    net_str = owner.get("network")
        except Exception:
            net_str = None
        if not net_str:
            return []
        return list(self._subnet_to_ifaces.get(net_str, []))

    def device_interfaces_evidence(self, device: str) -> List[Dict[str, Any]]:
        """Return interfaces list for a device (evidence only)."""
        self.query_count += 1
        d = self._resolve_device(device)
        if not d:
            return []
        dev = self.devices[d]
        out = []
        for iface in (dev.get("interfaces", []) or []):
            if not isinstance(iface, dict):
                continue
            out.append(
                {
                    "name": iface.get("name"),
                    "ipv4": iface.get("ipv4"),
                    "status": iface.get("status"),
                    "vrf": iface.get("vrf"),
                    "vlan": iface.get("vlan"),
                }
            )
        return out

    def device_routing_evidence(self, device: str) -> Dict[str, Any]:
        """Return routing-related blocks for a device (evidence only)."""
        self.query_count += 1
        d = self._resolve_device(device)
        if not d:
            return {}
        dev = self.devices[d]
        return {
            "routing": dev.get("routing", {}),
            "configuration_routing": dev.get("configuration", {}).get("routing", {}),
        }

    def calculate_routing_entries(self, device: str) -> int:
        self.query_count += 1
        if device not in self.devices:
            return 0
        dev = self.devices[device]
        # Dataset's "routing_table_entry_count" corresponds to connected interface entries (incl. Loopback),
        # i.e., the number of interfaces present in facts (4 for leaf*, 5 for p*/pe* in this dataset).
        if_list = dev.get('interfaces', []) or []
        try:
            # Prefer explicit list length when available
            if isinstance(if_list, list) and if_list:
                return len({(i.get('name') or str(i)) for i in if_list})
        except Exception:
            pass
        # Fallback to num_interfaces if present
        return int(dev.get('num_interfaces') or 0)

class NetConfigQAAgent:
    def __init__(self, facts_file: str, model: str = "gpt-4o-mini", backend: str = "openai_api", base_url: str = None, api_key: str = None, temperature: float = 0.0, phase: int = 3):
        self.backend = backend
        self.phase = phase  # Track experiment phase
        with open(facts_file, 'r', encoding='utf-8') as f:
            self.facts_data = json.load(f)
        self.facts_engine = FactsQueryEngine(self.facts_data)
        
        if backend == "vllm_server":
            base_llm = ChatOpenAI(model=model, temperature=temperature, api_key="EMPTY", base_url=base_url or "http://localhost:8000/v1")
            # Stop only when the model starts hallucinating an Observation.
            # IMPORTANT: Do NOT stop on "Thought:"; the ReAct format requires it and stopping there truncates outputs.
            self.llm = base_llm.bind(stop=["\nObservation:", "Observation:", "\nObservation", "Observation"])
        else:
            self.llm = ChatOpenAI(model=model, temperature=temperature, api_key=api_key or os.getenv("OPENAI_API_KEY"), base_url=base_url)
            
        # Base tools common to all phases
        base_tools = [
            Tool(name="query_device", func=self._query_device_wrapper, description="Query specific field for a device. Input format: 'device, field'"),
            Tool(name="list_all_devices", func=self.facts_engine.list_all_devices, description="List all hostnames or a specific field for all devices."),
            Tool(name="interface_status_map", func=self.facts_engine.interface_status_map, description="Get interface status map for a device. Returns a JSON object: {\"iface\": \"up/down\"}. Input: device hostname."),
            Tool(name="calculate_routing_entries", func=self.facts_engine.calculate_routing_entries, description="Get routing_table_entry_count for a device (connected interface entries incl. Loopback). Input: device hostname."),
        ]
        
        # Phase-specific tools
        if phase == 5:
            # Phase 5: Analysis/computation tools (e.g., Batfish integration)
            # Reserved for future implementation when comparing with automated analysis engines
            additional_tools = []
            logger.info("Phase 5: Analysis tools mode (reserved for Batfish/automated analysis)")
        else:
            # Phase 3 (default): Evidence-only tools for L4/L5 (LLM must reason; tools must NOT output paths/decisions)
            additional_tools = [
                Tool(name="ip_owner_evidence", func=self.facts_engine.ip_owner_evidence, description="Evidence only: given an IP, return owning device/interface info if present. Input: IP string."),
                Tool(name="subnet_members_evidence", func=self.facts_engine.subnet_members_evidence, description="Evidence only: given CIDR or IP, return interfaces in that subnet. Input: '172.16.1.0/24' or '172.16.1.2'."),
                Tool(name="device_interfaces_evidence", func=self.facts_engine.device_interfaces_evidence, description="Evidence only: return interface list (name/ipv4/status) for a device. Input: device hostname."),
                Tool(name="device_routing_evidence", func=self.facts_engine.device_routing_evidence, description="Evidence only: return routing/configuration.routing blocks for a device. Input: device hostname.")
            ]
            logger.info("Phase 3: Evidence-only tools mode (LLM reasoning required)")
        
        self.tools = base_tools + additional_tools
        
        template = """You are a network engineering assistant. Answer questions based on provided facts.
Available tools:
{tools}

DATA STRUCTURE REFERENCE:
The network facts for each device are organized as follows:
- system: [hostname, version, users (list), domain_name]
- interfaces: [list of objects with: name, ipv4, vlan, vrf, status]
- routing: [bgp (neighbors, local_as), ospf (process_ids, areas)]
- configuration:
    - security: [password_encryption (bool), banner_motd, banner_login, http_server (bool)]
    - routing: [static_routes_count (int), default_route_next_hops (list), bgp_as]
    - operational: [loopback_interfaces (list), snmp_communities]
    - advanced: [acls_count, prefix_lists_count, route_maps_count]
- num_interfaces: total number of interfaces (int)

Use these exact field names when calling 'query_device'. Examples:
- 'leaf1, hostname'
- 'p2, static_routes_count'
- 'leaf1, ssh_version_text'
- 'leaf1, vty_transport_input_text'
- 'leaf1, vty_login_mode_text'
- 'p1, aaa_authentication_method'

TIP:
- For interface status map questions, prefer the dedicated tool 'interface_status_map' to avoid formatting mistakes.
- For L4/L5 (reachability/traceroute/what-if), tools must provide ONLY evidence (facts). Do NOT use tools that output paths/decisions.
- Useful evidence tools:
  - ip_owner_evidence(ip)
  - subnet_members_evidence(cidr_or_ip)
  - device_interfaces_evidence(device)
  - device_routing_evidence(device)

STRICT FORMAT RULES:
1. Every response must begin with 'Thought:'. Do not repeat 'Thought:' multiple times.
2. To use a tool:
Thought: [Reasoning]
Action: [Tool name from: {tool_names}]
Action Input: [Input]

3. NEVER provide the 'Observation:' yourself. Stop generating immediately after providing the 'Action Input'.

4. After you receive an 'Observation' from the tool, you MUST provide a 'Thought' to analyze it.

5. Final Answer format:
   - For 'text': Final Answer: [Value]
   - For 'numeric': Final Answer: [Number]
   - For 'set': Final Answer: ["item1", "item2"] (MUST be valid JSON array with double quotes)
   - For 'map': Final Answer: {{"key1": "value1", "key2": "value2"}} (MUST be valid JSON object with double quotes)

Question: {input}
Answer Type: {answer_type}

{agent_scratchpad}"""
        
        prompt = PromptTemplate(template=template, input_variables=["input", "answer_type", "agent_scratchpad"], partial_variables={"tool_names": ", ".join([t.name for t in self.tools])})
        agent = create_react_agent(self.llm, self.tools, prompt)
        # L4/L5 questions often trigger occasional formatting slips. If we "force" stop at max_iterations,
        # we get lots of empty predictions ("Agent stopped...") which collapses accuracy.
        # Use a higher iteration budget and let the agent "generate" a final answer from partial work.
        self.agent_executor = AgentExecutor(
            agent=agent,
            tools=self.tools,
            verbose=True,
            max_iterations=25,
            handle_parsing_errors="Invalid format. Use: 'Thought: ...', 'Action: <tool>', 'Action Input: <input>' OR 'Final Answer: <answer>'. Do NOT add extra text.",
            return_intermediate_steps=True,
            early_stopping_method="generate",
        )
        self.metrics = []

    def _query_device_wrapper(self, input_str: str) -> Any:
        """Helper to handle multi-argument tool call from Agent"""
        # Clean the input: Remove any trailing "Observation" or "Thought" labels that the model might have hallucinated
        cleaned_input = input_str.split("Observation")[0].split("Thought")[0].strip()
        
        # #region agent log
        with open("/home/kilab_pyj/codespace/.cursor/debug.log", "a") as f:
            f.write(json.dumps({"location": "run_netconfigqa_eval_agent.py:202", "message": "wrapper input (cleaned)", "data": {"raw": input_str, "cleaned": cleaned_input}, "timestamp": time.time() * 1000, "hypothesisId": "B"}) + "\n")
        # #endregion
        
        try:
            if "," not in cleaned_input:
                # #region agent log
                with open("/home/kilab_pyj/codespace/.cursor/debug.log", "a") as f:
                    f.write(json.dumps({"location": "run_netconfigqa_eval_agent.py:206", "message": "comma missing in input", "data": {"input_str": cleaned_input}, "timestamp": time.time() * 1000, "hypothesisId": "B"}) + "\n")
                # #endregion
                return "Error: Input must be in 'device, field' format (comma separated)."
            
            parts = [p.strip().strip("'\"") for p in cleaned_input.split(",")]
            if len(parts) < 2:
                return "Error: Missing field name. Format: 'device, field'"
            
            res = self.facts_engine.query_device_info(parts[0], parts[1])
            
            # #region agent log
            with open("/home/kilab_pyj/codespace/.cursor/debug.log", "a") as f:
                f.write(json.dumps({"location": "run_netconfigqa_eval_agent.py:213", "message": "wrapper returning result", "data": {"device": parts[0], "field": parts[1], "result": str(res)[:100]}, "timestamp": time.time() * 1000, "hypothesisId": "B"}) + "\n")
            # #endregion
            return res
        except Exception as e:
            return f"Error in query_device: {str(e)}"

    def query(self, question: str, answer_type: str) -> tuple[str, QueryMetrics]:
        start_time = time.time()
        tool_calls_before = self.facts_engine.query_count
        try:
            # vLLM servers can occasionally drop connections; retry a few times with backoff.
            max_attempts = 3 if self.backend == "vllm_server" else 1
            last_err: Optional[Exception] = None
            result = None
            p_tokens = c_tokens = t_tokens = 0

            for attempt in range(1, max_attempts + 1):
                try:
                    if self.backend == "openai_api":
                        with get_openai_callback() as cb:
                            result = self.agent_executor.invoke({"input": question, "answer_type": answer_type})
                            p_tokens, c_tokens, t_tokens = cb.prompt_tokens, cb.completion_tokens, cb.total_tokens
                    else:
                        result = self.agent_executor.invoke({"input": question, "answer_type": answer_type})
                        c_tokens = count_tokens(result.get('output', ''))
                        p_tokens = count_tokens(question) + 500
                        t_tokens = p_tokens + c_tokens
                    last_err = None
                    break
                except Exception as e:
                    last_err = e
                    msg = str(e).lower()
                    retryable = ("connection error" in msg) or ("timed out" in msg) or ("timeout" in msg) or ("connection reset" in msg)
                    if attempt < max_attempts and retryable:
                        sleep_s = 0.5 * (2 ** (attempt - 1))
                        logger.warning(f"LLM call failed (attempt {attempt}/{max_attempts}): {e}. Retrying in {sleep_s:.1f}s")
                        time.sleep(sleep_s)
                        continue
                    raise
            if last_err is not None and result is None:
                raise last_err

            intermediate_steps = result.get('intermediate_steps', [])
            metrics = QueryMetrics(
                question_id="", total_time=time.time() - start_time,
                tool_calls=self.facts_engine.query_count - tool_calls_before,
                tool_call_details=[{'tool': a.tool, 'input': a.tool_input, 'output_len': len(str(o))} for a, o in intermediate_steps],
                prompt_tokens=p_tokens, completion_tokens=c_tokens, total_tokens=t_tokens,
                context_size=sum(len(str(o)) for _, o in intermediate_steps),
                agent_steps=len(intermediate_steps), success=True
            )
            return str(result.get('output', '')), metrics
        except Exception as e:
            logger.error(f"Query failed: {e}")
            return "Error", QueryMetrics("", 0, 0, [], 0, 0, 0, 0, 0, False, str(e))

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--facts", required=True)
    parser.add_argument("--questions", required=True)
    parser.add_argument("--model", default="GPT-OSS-20B")
    parser.add_argument("--backend", default="vllm_server")
    parser.add_argument("--base_url", default="http://localhost:8000/v1")
    parser.add_argument("--sample", type=int, default=None)
    parser.add_argument("--phase", type=int, default=3, choices=[3, 5], help="Experiment phase: 3=Evidence-only tools, 5=Analysis tools")
    args = parser.parse_args()

    logger.info(f"Starting NetConfigQA Agent evaluation (Phase {args.phase})")
    agent = NetConfigQAAgent(facts_file=args.facts, model=args.model, backend=args.backend, base_url=args.base_url, phase=args.phase)
    
    with open(args.questions, 'r', encoding='utf-8') as f:
        questions = json.load(f)
    
    # Handle case where questions is a dict instead of a list
    if isinstance(questions, dict) and 'questions' in questions:
        questions = questions['questions']
    
    if args.sample and isinstance(questions, list):
        questions = questions[:args.sample]
    
    results = []
    for i, q in enumerate(questions):
        # Use existing ID or fallback to index
        q_id = str(q.get('question_id') or q.get('id') or i)
        q_text = q.get('question') or q.get('input') or q.get('prompt', '')
        
        logger.info(f"Processing Q: {q_id}")
        answer_type = q.get('answer_type', 'text')
        pred_raw, metrics = agent.query(q_text, answer_type)
        pred = _normalize_prediction_by_type(pred_raw, answer_type)
        metrics.question_id = q_id
        agent.metrics.append(metrics)
        results.append({
            "question_id": q_id,
            "question": q_text,
            "gold": q.get('answer') or q.get('gold', ''),
            "pred": pred,
            "pred_raw": pred_raw,
            "answer_type": answer_type,
            "level": q.get('level', 'L1'),
            "category": q.get('category', 'General'),
            "status": q.get('status', 'OK'),
            "metrics": asdict(metrics)
        })

    # 지표 요약 계산
    total_q = len(questions)
    summary = {
        "avg_time_per_query": sum(m.total_time for m in agent.metrics) / total_q if total_q > 0 else 0,
        "avg_tool_calls": sum(m.tool_calls for m in agent.metrics) / total_q if total_q > 0 else 0,
        "avg_prompt_tokens": sum(m.prompt_tokens for m in agent.metrics) / total_q if total_q > 0 else 0,
        "avg_completion_tokens": sum(m.completion_tokens for m in agent.metrics) / total_q if total_q > 0 else 0,
        "avg_total_tokens": sum(m.total_tokens for m in agent.metrics) / total_q if total_q > 0 else 0,
        "avg_context_size": sum(m.context_size for m in agent.metrics) / total_q if total_q > 0 else 0,
        "total_tokens": sum(m.total_tokens for m in agent.metrics),
        "total_tool_calls": sum(m.tool_calls for m in agent.metrics),
        "success_rate": sum(1 for m in agent.metrics if m.success) / total_q if total_q > 0 else 0
    }

    # 결과 저장
    res_dir = f"results/{args.model.replace('/', '_')}_agent"
    os.makedirs(res_dir, exist_ok=True)
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    output_data = {
        "meta": {
            "model": args.model,
            "total_samples": total_q,
            "duration": sum(m.total_time for m in agent.metrics)
        },
        "metrics_summary": summary,
        "results": results
    }
    with open(f"{res_dir}/results_agent_{ts}.json", 'w', encoding='utf-8') as f:
        # ensure_ascii=False prevents Korean (and other non-ASCII) characters from being escaped as \uXXXX.
        json.dump(output_data, f, indent=2, ensure_ascii=False)
    logger.info(f"Saved results to {res_dir}")

if __name__ == "__main__":
    main()
