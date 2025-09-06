# Benchmark Survey


You are a research assistant helping to write an academic paper about a new dataset for network configuration parsing. I need you to find and analyze existing benchmarks and datasets that are relevant to our work.

## Research Task:
Find and analyze existing datasets/benchmarks in the following areas:

### Primary Areas (Most Important):
1. **Network Configuration Analysis**
   - Datasets for parsing network device configurations
   - Benchmarks for network topology understanding
   - Configuration file analysis datasets

2. **Infrastructure-as-Code (IaC) Datasets**
   - Terraform, Ansible, CloudFormation configuration datasets
   - Infrastructure configuration parsing benchmarks

3. **Code Understanding & Parsing**
   - Datasets for structured file parsing (XML, JSON, YAML)
   - Code comprehension benchmarks (CodeXGLUE, CodeBERT datasets)

### Secondary Areas:
4. **Domain-Specific Question Answering**
   - Technical documentation QA datasets
   - Domain-specific reading comprehension benchmarks

5. **Network Management & Monitoring**
   - Network troubleshooting datasets
   - Network performance analysis benchmarks

## For Each Dataset/Benchmark Found, Provide:
1. **Dataset Name** and **Paper Title**
2. **Authors** and **Publication Venue** (Conference/Journal, Year)
3. **Dataset Size** (number of samples, files, etc.)
4. **Domain Focus** (what specific area it covers)
5. **Task Type** (QA, classification, parsing, generation, etc.)
6. **Data Format** (what type of input/output)
7. **Evaluation Metrics** used
8. **Availability** (public/private, download link if available)
9. **Key Characteristics** that differentiate it from others

## Output Format:
Please structure your findings as a table with these columns:
| Dataset Name | Paper Title | Authors | Venue/Year | Size | Domain | Task Type | Data Format | Metrics | Available | Key Features |

## Additional Analysis:
After the table, please provide:
1. **Gap Analysis**: What aspects are missing in existing datasets that our NetworkConfigQA addresses?
2. **Positioning**: How does our focus on "real network topology parsing" differ from existing work?
3. **Comparison Points**: What metrics/characteristics should we highlight to show our dataset's novelty?

## Search Strategy:
Please search recent papers (2020-2024) from:
- NLP venues: ACL, EMNLP, NAACL, ICLR, NeurIPS
- Systems venues: NSDI, OSDI, SIGCOMM, IMC
- AI venues: AAAI, IJCAI
- Domain-specific: NOMS, IM, CNSM (network management conferences)

Look for keywords: "network configuration", "configuration parsing", "network topology", "infrastructure as code", "code understanding", "structured data parsing", "network dataset"
