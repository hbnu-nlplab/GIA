# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Development Commands

### Core Pipeline Execution
```bash
# Main demo - runs full 6-stage pipeline
python demo_implementation.py

# Test specific components
python test_evaluation_system.py
python test_evidence_system.py
python test_command_metrics.py

# Generate dataset reports
python dataset_report_generator.py
```

### Environment Setup
```bash
# Install dependencies
pip install -r requirements.txt

# Environment variables for development (optional)
set OPENAI_API_KEY=your_api_key_here
set GIA_USE_INTENT_LLM=0      # Disable LLM for development (recommended)
set GIA_ENABLE_LLM_REVIEW=0   # Disable LLM review for development
```

### Testing
This project uses custom test files rather than pytest or unittest:
- `test_evaluation_system.py` - Tests evaluation components
- `test_evidence_system.py` - Tests evidence generation
- `test_command_metrics.py` - Tests command metrics

Run tests individually with `python test_<filename>.py`

## Architecture Overview

### Core Pipeline (integrated_pipeline.py)
The main system follows a 6-stage pipeline:
1. **PARSING** - XML network configs → structured JSON facts
2. **BASIC_GENERATION** - Rule-based question generation
3. **ENHANCED_GENERATION** - LLM-based advanced questions
4. **ASSEMBLY** - Combine and organize questions by complexity
5. **VALIDATION** - Quality checks and filtering
6. **EVALUATION** - Multi-dimensional scoring

### Key Components

#### Parsers Module (`parsers/`)
- `UniversalParser` - Main entry point for XML parsing
- `parsers/vendor/` - Vendor-specific parsers (currently XR-focused)
- Converts network device XML configs to standardized JSON structure

#### Generators Module (`generators/`)
- `RuleBasedGenerator` - Policy-driven systematic question generation
- `EnhancedLLMQuestionGenerator` - LLM-based advanced question creation
- Uses `policies/policies.json` for generation rules

#### Core Engine (`utils/builder_core.py`)
- `BuilderCore` - Central metrics calculation engine
- Computes network-specific metrics (BGP, SSH, VRF, OSPF, etc.)
- Supports ~50+ different network metrics for question answering

#### Answer System
- `answer_agent.py` - Generates detailed answers with evidence
- `command_agent.py` - Handles command-based questions
- Both use `BuilderCore` for metric calculations

#### Quality Systems
- `inspectors/evaluation_system.py` - Multi-profile evaluation
- `inspectors/intent_inspector.py` - Question intent analysis
- `assemblers/test_assembler.py` - Dataset assembly and organization

### Configuration

#### Global Settings (`config/settings.yaml`)
- API configuration (OpenAI, timeouts, retries)
- Model assignments per pipeline stage
- Feature toggles (LLM usage, review stages)
- Generation quotas per category

#### Policies (`policies/policies.json`)
- Question generation rules by category
- Target metrics and complexity levels
- Supports: Security_Policy, BGP_Consistency, VRF_Consistency, etc.

### Data Flow
```
XML Files (XML_Data/) 
  → UniversalParser 
  → BuilderCore (metrics) 
  → RuleBasedGenerator + EnhancedLLMQuestionGenerator 
  → TestAssembler 
  → ComprehensiveEvaluator 
  → Final Dataset (demo_output/)
```

### Output Structure
All pipeline runs create organized outputs in `demo_output/`:
- `basic_dataset.json` - Rule-based questions
- `enhanced_dataset.json` - LLM-generated questions  
- `assembled_*.json` - Questions grouped by complexity
- `train.json`, `validation.json`, `test.json` - ML-ready splits
- `metadata.json` - Generation configuration and statistics

## Development Guidelines

### Adding New Metrics
1. Add calculation logic to `utils/builder_core.py`
2. Register in the `calculate_metric()` method
3. Update policies if needed for question generation

### Adding New Question Categories
1. Define in `policies/policies.json` 
2. Implement generation logic in appropriate generator
3. Test with existing evaluation system

### Working with LLM Features
- Keep `GIA_USE_INTENT_LLM=0` during development to avoid API costs
- Use `GIA_ENABLE_LLM_REVIEW=0` to disable quality review steps
- LLM features are primarily in enhanced generation and evaluation

### Debugging
- Enable detailed logging: set logging level to DEBUG in settings.yaml
- Use debug scripts in `debug/` folder for component testing
- Check `demo_output/metadata.json` for pipeline execution details

## File Naming Conventions
- `test_*.py` - Test files (run individually, not with pytest)
- `debug_*.py` - Debug and development utilities
- `*_agent.py` - Question/answer processing agents
- `*_generator.py` - Question generation components
- `*_assembler.py` - Dataset assembly and organization