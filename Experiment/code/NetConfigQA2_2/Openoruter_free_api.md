 NetAlly/.venv/bin/python Experiment/code/NetConfigQA2_2/run_eval_vllm_offline.py --model openrouter-gpt-oss-120b-free --lab A

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

export OPENROUTER_API_KEY=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 
export OPENROUTER_SITE_URL=http://localhost
export OPENROUTER_APP_NAME=NetConfigQA2_2


---






# 1. nvidia/nemotron-3-super-120b-a12b:free
- https://openrouter.ai/nvidia/nemotron-3-super-120b-a12b:free
- nvidia/nemotron-3-super-120b-a12b:free

NVIDIA Nemotron 3 Super is a 120B-parameter open hybrid MoE model, activating just 12B parameters for maximum compute efficiency and accuracy in complex multi-agent applications. Built on a hybrid Mamba-Transformer Mixture-of-Experts architecture with multi-token prediction (MTP), it delivers over 50% higher token generation compared to leading open models.

The model features a 1M token context window for long-term agent coherence, cross-document reasoning, and multi-step task planning. Latent MoE enables calling 4 experts for the inference cost of only one, improving intelligence and generalization. Multi-environment RL training across 10+ environments delivers leading accuracy on benchmarks including AIME 2025, TerminalBench, and SWE-Bench Verified.

Fully open with weights, datasets, and recipes under the NVIDIA Open License, Nemotron 3 Super allows easy customization and secure deployment anywhere — from workstation to cloud.


OpenRouter supports reasoning-enabled models that can show their step-by-step thinking process. Use the reasoning parameter in your request to enable reasoning, and access the reasoning_details array in the response to see the model's internal reasoning before the final answer. When continuing a conversation, preserve the complete reasoning_details when passing messages back to the model so it can continue reasoning from where it left off. Learn more about reasoning tokens.

In the examples below, the OpenRouter-specific headers are optional. Setting them allows your app to appear on the OpenRouter leaderboards.


```python
from openai import OpenAI

client = OpenAI(
  base_url="https://openrouter.ai/api/v1",
  api_key="<OPENROUTER_API_KEY>",
)

# First API call with reasoning
response = client.chat.completions.create(
  model="nvidia/nemotron-3-super-120b-a12b:free",
  messages=[
          {
            "role": "user",
            "content": "How many r's are in the word 'strawberry'?"
          }
        ],
  extra_body={"reasoning": {"enabled": True}}
)

# Extract the assistant message with reasoning_details
response = response.choices[0].message

# Preserve the assistant message with reasoning_details
messages = [
  {"role": "user", "content": "How many r's are in the word 'strawberry'?"},
  {
    "role": "assistant",
    "content": response.content,
    "reasoning_details": response.reasoning_details  # Pass back unmodified
  },
  {"role": "user", "content": "Are you sure? Think carefully."}
]

# Second API call - model continues reasoning from where it left off
response2 = client.chat.completions.create(
  model="nvidia/nemotron-3-super-120b-a12b:free",
  messages=messages,
  extra_body={"reasoning": {"enabled": True}}
)
```


# 2. minimax/minimax-m2.5:free

- https://openrouter.ai/minimax/minimax-m2.5:free
- minimax/minimax-m2.5:free

Released Feb 12, 2026
196,608 context
$0/M input tokens
$0/M output tokens
MiniMax-M2.5 is a SOTA large language model designed for real-world productivity. Trained in a diverse range of complex real-world digital working environments, M2.5 builds upon the coding expertise of M2.1 to extend into general office work, reaching fluency in generating and operating Word, Excel, and Powerpoint files, context switching between diverse software environments, and working across different agent and human teams. Scoring 80.2% on SWE-Bench Verified, 51.3% on Multi-SWE-Bench, and 76.3% on BrowseComp, M2.5 is also more token efficient than previous generations, having been trained to optimize its actions and output through planning.

```py
from openai import OpenAI

client = OpenAI(
  base_url="https://openrouter.ai/api/v1",
  api_key="<OPENROUTER_API_KEY>",
)

# First API call with reasoning
response = client.chat.completions.create(
  model="minimax/minimax-m2.5:free",
  messages=[
          {
            "role": "user",
            "content": "How many r's are in the word 'strawberry'?"
          }
        ],
  extra_body={"reasoning": {"enabled": True}}
)

# Extract the assistant message with reasoning_details
response = response.choices[0].message

# Preserve the assistant message with reasoning_details
messages = [
  {"role": "user", "content": "How many r's are in the word 'strawberry'?"},
  {
    "role": "assistant",
    "content": response.content,
    "reasoning_details": response.reasoning_details  # Pass back unmodified
  },
  {"role": "user", "content": "Are you sure? Think carefully."}
]

# Second API call - model continues reasoning from where it left off
response2 = client.chat.completions.create(
  model="minimax/minimax-m2.5:free",
  messages=messages,
  extra_body={"reasoning": {"enabled": True}}
)
```



# 3. nvidia/nemotron-3-nano-30b-a3b:free

- https://openrouter.ai/nvidia/nemotron-3-nano-30b-a3b:free
- nvidia/nemotron-3-nano-30b-a3b:free

Note: For the free endpoint, all prompts and output are logged to improve the provider's model and its product and services. Please do not upload any personal, confidential, or otherwise sensitive information. This is a trial use only. Do not use for production or business-critical systems.

nvidia/nemotron-3-nano-30b-a3b:free

Released Dec 14, 2025
256,000 context
$0/M input tokens
$0/M output tokens
NVIDIA Nemotron 3 Nano 30B A3B is a small language MoE model with highest compute efficiency and accuracy for developers to build specialized agentic AI systems.

The model is fully open with open-weights, datasets and recipes so developers can easily
customize, optimize, and deploy the model on their infrastructure for maximum privacy and


```py
from openai import OpenAI

client = OpenAI(
  base_url="https://openrouter.ai/api/v1",
  api_key="<OPENROUTER_API_KEY>",
)

# First API call with reasoning
response = client.chat.completions.create(
  model="nvidia/nemotron-3-nano-30b-a3b:free",
  messages=[
          {
            "role": "user",
            "content": "How many r's are in the word 'strawberry'?"
          }
        ],
  extra_body={"reasoning": {"enabled": True}}
)

# Extract the assistant message with reasoning_details
response = response.choices[0].message

# Preserve the assistant message with reasoning_details
messages = [
  {"role": "user", "content": "How many r's are in the word 'strawberry'?"},
  {
    "role": "assistant",
    "content": response.content,
    "reasoning_details": response.reasoning_details  # Pass back unmodified
  },
  {"role": "user", "content": "Are you sure? Think carefully."}
]

# Second API call - model continues reasoning from where it left off
response2 = client.chat.completions.create(
  model="nvidia/nemotron-3-nano-30b-a3b:free",
  messages=messages,
  extra_body={"reasoning": {"enabled": True}}
)
```


# 4. openai/gpt-oss-120b:free
- https://openrouter.ai/openai/gpt-oss-120b:free
- openai/gpt-oss-120b:free


Released Aug 5, 2025
131,072 context
$0/M input tokens
$0/M output tokens
gpt-oss-120b is an open-weight, 117B-parameter Mixture-of-Experts (MoE) language model from OpenAI designed for high-reasoning, agentic, and general-purpose production use cases. It activates 5.1B parameters per forward pass and is optimized to run on a single H100 GPU with native MXFP4 quantization. The model supports configurable reasoning depth, full chain-of-thought access, and native tool use, including function calling, browsing, and structured output generation.


```py
from openai import OpenAI

client = OpenAI(
  base_url="https://openrouter.ai/api/v1",
  api_key="<OPENROUTER_API_KEY>",
)

# First API call with reasoning
response = client.chat.completions.create(
  model="openai/gpt-oss-120b:free",
  messages=[
          {
            "role": "user",
            "content": "How many r's are in the word 'strawberry'?"
          }
        ],
  extra_body={"reasoning": {"enabled": True}}
)

# Extract the assistant message with reasoning_details
response = response.choices[0].message

# Preserve the assistant message with reasoning_details
messages = [
  {"role": "user", "content": "How many r's are in the word 'strawberry'?"},
  {
    "role": "assistant",
    "content": response.content,
    "reasoning_details": response.reasoning_details  # Pass back unmodified
  },
  {"role": "user", "content": "Are you sure? Think carefully."}
]

# Second API call - model continues reasoning from where it left off
response2 = client.chat.completions.create(
  model="openai/gpt-oss-120b:free",
  messages=messages,
  extra_body={"reasoning": {"enabled": True}}
)
```


# 5. qwen/qwen3-coder:free
- https://openrouter.ai/qwen/qwen3-coder:free
- qwen/qwen3-coder:free


Qwen3-Coder-480B-A35B-Instruct is a Mixture-of-Experts (MoE) code generation model developed by the Qwen team. It is optimized for agentic coding tasks such as function calling, tool use, and long-context reasoning over repositories. The model features 480 billion total parameters, with 35 billion active per forward pass (8 out of 160 experts).

Pricing for the Alibaba endpoints varies by context length. Once a request is greater than 128k input tokens, the higher pricing is used.

```py
from openai import OpenAI

client = OpenAI(
  base_url="https://openrouter.ai/api/v1",
  api_key="<OPENROUTER_API_KEY>",
)

completion = client.chat.completions.create(
  extra_headers={
    "HTTP-Referer": "<YOUR_SITE_URL>", # Optional. Site URL for rankings on openrouter.ai.
    "X-OpenRouter-Title": "<YOUR_SITE_NAME>", # Optional. Site title for rankings on openrouter.ai.
  },
  extra_body={},
  model="qwen/qwen3-coder:free",
  messages=[
    {
      "role": "user",
      "content": "What is the meaning of life?"
    }
  ]
)
print(completion.choices[0].message.content)
```



6. qwen/qwen3-next-80b-a3b-instruct:free
- https://openrouter.ai/qwen/qwen3-next-80b-a3b-instruct:free
- qwen/qwen3-next-80b-a3b-instruct:free

Released Sep 11, 2025
262,144 context
$0/M input tokens
$0/M output tokens
Qwen3-Next-80B-A3B-Instruct is an instruction-tuned chat model in the Qwen3-Next series optimized for fast, stable responses without “thinking” traces. It targets complex tasks across reasoning, code generation, knowledge QA, and multilingual use, while remaining robust on alignment and formatting. Compared with prior Qwen3 instruct variants, it focuses on higher throughput and stability on ultra-long inputs and multi-turn dialogues, making it well-suited for RAG, tool use, and agentic workflows that require consistent final answers rather than visible chain-of-thought.

The model employs scaling-efficient training and decoding to improve parameter efficiency and inference speed, and has been validated on a broad set of public benchmarks where it reaches or approaches larger Qwen3 systems in several categories while outperforming earlier mid-sized baselines. It is best used as a general assistant, code helper, and long-context task solver in production settings where deterministic, instruction-following outputs are preferred.


```py
from openai import OpenAI

client = OpenAI(
  base_url="https://openrouter.ai/api/v1",
  api_key="<OPENROUTER_API_KEY>",
)

completion = client.chat.completions.create(
  extra_headers={
    "HTTP-Referer": "<YOUR_SITE_URL>", # Optional. Site URL for rankings on openrouter.ai.
    "X-OpenRouter-Title": "<YOUR_SITE_NAME>", # Optional. Site title for rankings on openrouter.ai.
  },
  extra_body={},
  model="qwen/qwen3-next-80b-a3b-instruct:free",
  messages=[
    {
      "role": "user",
      "content": "What is the meaning of life?"
    }
  ]
)
print(completion.choices[0].message.content)
```

