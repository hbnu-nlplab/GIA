import os
import json
import logging
import time
import datetime
import argparse
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
            'static_routes': lambda d: d.get('configuration', {}).get('routing', {}).get('static_routes_count'),
            'static_route_count': lambda d: d.get('configuration', {}).get('routing', {}).get('static_routes_count'),
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

    def calculate_routing_entries(self, device: str) -> int:
        self.query_count += 1
        if device not in self.devices: return 0
        dev = self.devices[device]
        # Return static_routes_count from configuration section
        return dev.get('configuration', {}).get('routing', {}).get('static_routes_count', 0)

class NetConfigQAAgent:
    def __init__(self, facts_file: str, model: str = "gpt-4o-mini", backend: str = "openai_api", base_url: str = None, api_key: str = None, temperature: float = 0.0):
        self.backend = backend
        with open(facts_file, 'r') as f: self.facts_data = json.load(f)
        self.facts_engine = FactsQueryEngine(self.facts_data)
        
        if backend == "vllm_server":
            base_llm = ChatOpenAI(model=model, temperature=temperature, api_key="EMPTY", base_url=base_url or "http://localhost:8000/v1")
            # Stronger stop sequences to prevent model from hallucinating labels
            self.llm = base_llm.bind(stop=["\nObservation:", "Observation:", "\nObservation", "Observation", "\nThought:", "Thought:"])
        else:
            self.llm = ChatOpenAI(model=model, temperature=temperature, api_key=api_key or os.getenv("OPENAI_API_KEY"), base_url=base_url)
            
        self.tools = [
            Tool(name="query_device", func=self._query_device_wrapper, description="Query specific field for a device. Input format: 'device, field'"),
            Tool(name="list_all_devices", func=self.facts_engine.list_all_devices, description="List all hostnames or a specific field for all devices."),
            Tool(name="calculate_routing_entries", func=self.facts_engine.calculate_routing_entries, description="Get the number of routing entries (static routes) for a device.")
        ]
        
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

Use these exact field names when calling 'query_device'. For example: 'leaf1, hostname' or 'p2, static_routes_count'.

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
   - For 'set': Final Answer: ['item1', 'item2'] (Always use a Python-style list format)

Question: {input}
Answer Type: {answer_type}

{agent_scratchpad}"""
        
        prompt = PromptTemplate(template=template, input_variables=["input", "answer_type", "agent_scratchpad"], partial_variables={"tool_names": ", ".join([t.name for t in self.tools])})
        agent = create_react_agent(self.llm, self.tools, prompt)
        self.agent_executor = AgentExecutor(agent=agent, tools=self.tools, verbose=True, max_iterations=10, handle_parsing_errors=True, return_intermediate_steps=True, early_stopping_method="force")
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
            if self.backend == "openai_api":
                with get_openai_callback() as cb:
                    result = self.agent_executor.invoke({"input": question, "answer_type": answer_type})
                    p_tokens, c_tokens, t_tokens = cb.prompt_tokens, cb.completion_tokens, cb.total_tokens
            else:
                result = self.agent_executor.invoke({"input": question, "answer_type": answer_type})
                c_tokens = count_tokens(result.get('output', ''))
                p_tokens = count_tokens(question) + 500
                t_tokens = p_tokens + c_tokens

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
    args = parser.parse_args()

    agent = NetConfigQAAgent(facts_file=args.facts, model=args.model, backend=args.backend, base_url=args.base_url)
    
    with open(args.questions, 'r') as f:
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
        pred, metrics = agent.query(q_text, q.get('answer_type', 'text'))
        metrics.question_id = q_id
        agent.metrics.append(metrics)
        results.append({
            "question_id": q_id,
            "question": q_text,
            "gold": q.get('answer') or q.get('gold', ''),
            "pred": pred,
            "answer_type": q.get('answer_type', 'text'),
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
    with open(f"{res_dir}/results_agent_{ts}.json", 'w') as f:
        json.dump(output_data, f, indent=2)
    logger.info(f"Saved results to {res_dir}")

if __name__ == "__main__":
    main()
