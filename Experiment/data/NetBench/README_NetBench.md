---
license: mit
task_categories:
- question-answering
- text-generation
language:
- en
tags:
- slm
- telecom
- network-sme
- ran
size_categories:
- 1K<n<10K
citations:
  - title: "Efficient Telecom Specific LLM: TSLAM-Mini with QLoRA and Digital Twin Data"
    authors: "Vignesh Ethiraj, Divya Vijay, Sidhanth Menon"
    url: "https://arxiv.org/abs/2505.07877"
    arxiv_id: "arXiv:2505.07877v1 [cs.NI]"
    description: "This paper introduces TSLAM-Mini, a 3.8-billion parameter telecom-specific language model fine-tuned using QLoRA and a dataset of 100,000 samples from NetoAI's DigiTwin platform, covering 20 telecommunications use-cases. It demonstrates superior performance in network-related tasks, leveraging digital twin data and PEFT methodologies."

extra_gated_prompt: "Please provide answers to the below questions to gain access to the model"
extra_gated_fields:
  Company: text
  Full Name: text
  Requests from Personal email IDs will be rejected by default Provide college or business email ID: text
  I want to use this Dataset for:
    type: select
    options: 
      - Research
      - Education
      - Commercial
      - label: Other
        value: other
---
## NetBench Dataset

![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-Follow-blue?logo=linkedin&style=flat-square)](https://www.linkedin.com/company/netoai/posts/?feedView=all)

## Dataset Overview

The **NetBench Dataset** is a curated collection of expert-level question-answer pairs designed to benchmark the ability of large language models (LLMs) to achieve network subject matter expert (SME) intelligence across 20 critical telecommunications and network engineering categories. These categories include:

- **Network Fundamentals & L2 Switching**: Basic device access, Layer 2 concepts (VLANs, STP, LAG), L2 security, and interface configuration.
- **IP Routing Protocols (IGP)**: OSPF, IS-IS, EIGRP configuration, verification, troubleshooting, and advanced features.
- **IP Routing Protocols (BGP)**: BGP peering, path selection, attributes, policy, scaling, and security (RPKI, BGPsec).
- **MPLS & Related Technologies**: LDP, RSVP-TE, MPLS L3VPNs, L2VPNs (VPLS, VPWS, EVPN), Segment Routing, and OAM.
- **Network Services & QoS**: NAT, DHCP, DNS, Multicast, First Hop Redundancy (HSRP, VRRP, GLBP), and QoS techniques.
- **Network Security (Core Principles & Firewalls)**: AAA, ZTA, encryption, PKI, ACLs, ZBFW, SRX Policies, and threat mitigation.
- **Network Security (Advanced & Operations)**: IPS, UTM, VPNs (IPsec, SSL), SIEM, NDR, EDR, and SecOps practices.
- **Network Management & Monitoring (Protocols)**: SNMP, NETCONF, RESTCONF, and their operations.
- **Network Management & Monitoring (Operations & Tools)**: Fault/performance management, Syslog, NTP, IP SLA, and diagnostics.
- **Network Automation & Orchestration**: IaC, CI/CD, Ansible, Terraform, Python libraries, ZTP, and workflow engines.
- **OSS (Operations Support Systems)**: Inventory, activation, assurance, discovery, and reconciliation.
- **BSS (Business Support Systems)**: CRM, ordering, billing, charging, and partner management.
- **OSS/BSS Integration & Evolution**: TM Forum frameworks, system modernization, and AI impact.
- **Radio Access Networks (RAN - LTE/5G Fundamentals)**: LTE/5G architecture, air interface, and core protocols.
- **Radio Access Networks (RAN - Advanced Features & Optimization)**: MIMO, Beamforming, CA, SON, and KPIs.
- **Mobile Core Networks (EPC & 5GC)**: EPC and 5GC architecture, interfaces, and procedures.
- **Satellite Communications (SatCom)**: Orbits, frequency bands, link budgets, and applications (DTH, VSAT).
- **Transport Networks (Optical, Ethernet, Submarine)**: DWDM, OTN, Carrier Ethernet, and submarine systems.
- **Cloud Networking & Virtualization (NFV/SDN)**: Cloud networking, NFV, SDN, and Kubernetes CNI.
- **Ethical AI & Societal Impact**: Bias, privacy, explainability, and governance in telecom AI.

Curated through collaboration with telecom industry leaders and the NetoAI DigiTwin platform, the dataset captures realistic network scenarios via digital twin simulations and knowledge distilled from large foundation models. It supports the development of Small Language Models (SLMs), intelligent network diagnostics, and educational platforms for telecom professionals, offering vendor-agnostic insights for modern network engineering challenges.
For more details, see the research paper: ["Efficient Telecom Specific LLM: TSLAM-Mini with QLoRA and Digital Twin Data"](https://arxiv.org/abs/2505.07877).


## Languages

- English (`en`)



## Dataset Structure

Each instance contains a question-answer pair with associated contextual information. The dataset is provided in tabular formats such as CSV or JSON, with the following columns:

| Field          | Type    | Description                                                   |
|----------------|---------|---------------------------------------------------------------|
| `Main Category`| String  | High-level network domain (e.g., Network - Configuration)     |
| `Category`     | String  | Specific sub-domain or protocol (e.g., Routing Protocols Config) |
| `Scenario_ID`  | Integer | Unique identifier for each scenario                           |
| `Context`      | String  | Background description or scenario context                    |
| `Question`     | String  | Technical question related to the scenario                    |
| `Answer`       | String  | Expert-level, detailed response with reasoning and best practices |



## Data Splits

- **Size:** Approximately 5390 instances  

- No predefined splits — users can create custom train/test splits based on `Main Category`, `Category`, or other criteria.


## Dataset Creation

- **Curation Rationale:**  
  To create a high-quality, expert-validated dataset addressing real-world network engineering problems to foster AI-driven automation, diagnostics, and education.

- **Source Data:**  
  Contributions from network subject matter experts (SMEs) referencing authentic industry scenarios and standards.

- **Annotations:**  
  Answers are composed and reviewed by SMEs for technical accuracy, clarity, and adherence to best practices and networking protocols.



## Example Data Instance

| Main Category           | Category                        | Scenario_ID | Context                                                                                      | Question                                                                                         | Answer                                                                                                                                                                                                                                   |
|------------------------|--------------------------------|-------------|----------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Network - Configuration | Routing Protocols Config (All Vendors) | 461         | BGP Path Selection: Router receives two paths for prefix 10.1.0.0/16. Path A: Higher Local Preference, Longer AS_PATH. Path B: Lower Local Preference, Shorter AS_PATH. | Which BGP path (A or B) will the router prefer by default for prefix 10.1.0.0/16, and why?      | Path A will be preferred. BGP path selection prioritizes the path with the highest Local Preference before considering AS_PATH length. Although Path B has a shorter AS_PATH, Path A’s higher Local Preference makes it more desirable. |



## Usage Example

Here is an example of how to load and filter the dataset using Python:

```python
import pandas as pd

# Load the dataset
df = pd.read_csv("NetBench.csv")

# Filter scenarios related to BGP routing configuration
bgp_scenarios = df[df["Category"] == "Routing Protocols Config (All Vendors)"]

# Display sample questions and answers
print(bgp_scenarios[["Question", "Answer"]].head())
```



## Limitations and Considerations

* **Scenario Selection Bias:**
  Focuses mainly on commonly used protocols such as BGP and OSPF; niche or emerging technologies may be underrepresented.

* **Vendor Bias:**
  While vendor-agnostic, scenarios may implicitly reflect common vendors like Cisco or Juniper.

* **Size:**
  Dataset size (5.39k) may not cover all possible edge cases.

* **Language:**
  English-only dataset limits accessibility to non-English speakers.

* **Vendor-Specificity:**
  Some answers might require vendor-specific interpretation when applied practically.



## Social Impact

This dataset supports advancements in telecom network automation, troubleshooting, and education — improving operational efficiency and helping train the next generation of network professionals.



## Future Directions

* Expanding coverage to emerging network technologies (e.g., 6G, SDN, NFV).
* Adding multilingual support to increase global accessibility.
* Introducing metadata such as difficulty level and vendor specificity for more granular use.





## License

This dataset is released under the [MIT License](https://opensource.org/licenses/MIT).



## Citation

If you use this dataset, please cite it as:

```bibtex
@dataset{NetBench,
  title       = {NetBench Dataset},
  author      = {[NetoAi]},
  year        = {2025},
  url         = {https://netoai.ai/},
  license     = {MIT}
}
```



## Contact
- For questions or contributions, visit https://www.netoai.ai.



---


