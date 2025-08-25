import os
import yaml
from pathlib import Path
from typing import Any, Dict, Optional, List
from dotenv import load_dotenv
from pydantic import BaseModel, Field


class ApiSettings(BaseModel):
    timeout: int = Field(60, env="OPENAI_TIMEOUT_SEC")
    max_retries: int = Field(2, env="OPENAI_MAX_RETRIES")
    base_url: Optional[str] = Field(None, env="OPENAI_BASE_URL")
    api_key: Optional[str] = Field(None, env="OPENAI_API_KEY")
    org_id: Optional[str] = Field(None, env="OPENAI_ORG_ID")
    project: Optional[str] = Field(None, env="OPENAI_PROJECT_ID")


class ModelsSettings(BaseModel):
    default: str = "gpt-4o-mini"
    paraphrase: str = Field("gpt-4o-mini", env="OPENAI_MODEL_PARAPHRASE")
    question_generation: str = Field("gpt-4o-mini", env="OPENAI_MODEL_QUESTION")
    intent_parsing: str = Field("gpt-4o-mini", env="OPENAI_MODEL_INTENT")
    hypothesis_review: str = Field("gpt-4o-mini", env="OPENAI_MODEL_HYPO_REVIEW")
    answer_synthesis: str = Field("gpt-4o-mini", env="OPENAI_MODEL_ANSWER_SYNTH")
    enhanced_generation: str = Field("gpt-4o", env="OPENAI_MODEL_ENHANCED_GEN")


class FeaturesSettings(BaseModel):
    use_intent_llm: bool = Field(True, env="GIA_USE_INTENT_LLM")
    enable_llm_review: bool = Field(True, env="GIA_ENABLE_LLM_REVIEW")
    disable_hypo_review: bool = Field(False, env="GIA_DISABLE_HYPO_REVIEW")


class GenerationSettings(BaseModel):
    basic_questions_per_category: int = 3
    enhanced_questions_per_category: int = 2


class LoggingSettings(BaseModel):
    level: str = "INFO"
    format: str = "%(asctime)s - %(levelname)s - %(message)s"


class Settings(BaseModel):
    api: ApiSettings = ApiSettings()
    models: ModelsSettings = ModelsSettings()
    features: FeaturesSettings = FeaturesSettings()
    generation: GenerationSettings = GenerationSettings()
    logging: LoggingSettings = LoggingSettings()


class ConfigManager:
    _instance = None

    @classmethod
    def get_instance(cls) -> 'ConfigManager':
        if cls._instance is None:
            cls._instance = ConfigManager()
        return cls._instance

    def __init__(self):
        if hasattr(self, 'settings'):
            return

        load_dotenv()

        config_dir = os.environ.get("GIA_CONFIG_DIR", "config")
        env = os.environ.get("GIA_ENV", "")

        base_config = self._load_yaml(config_dir, "settings.yaml")

        if env:
            env_config = self._load_yaml(config_dir, f"settings.{env}.yaml")
            self._deep_update(base_config, env_config)

        self.settings = Settings.model_validate(base_config)

    def _load_yaml(self, config_dir: str, filename: str) -> Dict[str, Any]:
        config_path = Path(config_dir) / filename
        if not config_path.exists():
            return {}
        with open(config_path, 'r', encoding='utf-8') as f:
            return yaml.safe_load(f) or {}

    def _deep_update(self, base_dict: Dict, update_dict: Dict) -> None:
        for key, value in update_dict.items():
            if isinstance(value, dict) and key in base_dict and isinstance(base_dict[key], dict):
                self._deep_update(base_dict[key], value)
            else:
                base_dict[key] = value

    def get_model(self, purpose: str) -> str:
        return getattr(self.settings.models, purpose, self.settings.models.default)

    def is_feature_enabled(self, feature_name: str) -> bool:
        return getattr(self.settings.features, feature_name, False)

    def get_api_config(self) -> ApiSettings:
        return self.settings.api


def get_config() -> ConfigManager:
    return ConfigManager.get_instance()


def get_settings() -> Settings:
    return get_config().settings
