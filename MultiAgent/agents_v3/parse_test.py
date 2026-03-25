import json
import re

text = """```json
{
    "status": "ACCEPT",
    "con_argument": "Agent 3's answer 'P2' is directly supported by the Passage, which states 'hostname P2'. Agent 4's defense correctly interprets the Passage and explains the relevance of the hostname command in network engineering.",
    "feedback_to_agent1": ""
}
```"""

json_match = re.search(r'\{.*\}', text.replace('\n', ' '), re.DOTALL)
result = json.loads(json_match.group(0)) if json_match else json.loads(text)
print(result)

text2 = """Agent 3's answer 'P2' is directly supported by the Passage, which states 'hostname P2'. Agent 4's defense correctly interprets the Passage and explains the relevance of the hostname command in network engineering."""

try:
    json_match = re.search(r'\{.*\}', text2.replace('\n', ' '), re.DOTALL)
    result = json.loads(json_match.group(0)) if json_match else json.loads(text2)
    print(result)
except Exception as e:
    print(f"Error for text2: {e}")

