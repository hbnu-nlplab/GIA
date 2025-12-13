import os
import yaml
from pathlib import Path
from typing import Any, Dict, Optional, List
from dotenv import load_dotenv
from pydantic import BaseModel, Field, AliasChoices
from pydantic_settings import BaseSettings, SettingsConfigDict


class ApiSettings(BaseSettings):
    model_config = SettingsConfigDict(env_file='.env', extra='ignore')
    
    timeout: int = Field(180, validation_alias=AliasChoices("OPENAI_TIMEOUT_SEC"))
    max_retries: int = Field(2, validation_alias=AliasChoices("OPENAI_MAX_RETRIES"))
    base_url: Optional[str] = Field(None, validation_alias=AliasChoices("OPENAI_BASE_URL"))
    api_key: Optional[str] = Field(None, validation_alias=AliasChoices("OPENAI_API_KEY"))
    org_id: Optional[str] = Field(None, validation_alias=AliasChoices("OPENAI_ORG_ID"))
    project: Optional[str] = Field(None, validation_alias=AliasChoices("OPENAI_PROJECT_ID"))


class ModelsSettings(BaseSettings):
    model_config = SettingsConfigDict(env_file='.env', extra='ignore')
    
    # GPT-5 기반 권장 기본값 (YAML/ENV로 자유롭게 오버라이드)
    default: str = "gpt-5-mini-2025-08-07"
    paraphrase: str = Field("gpt-5-mini-2025-08-07", validation_alias=AliasChoices("OPENAI_MODEL_PARAPHRASE"))
    question_generation: str = Field("gpt-5-mini-2025-08-07", validation_alias=AliasChoices("OPENAI_MODEL_QUESTION"))
    intent_parsing: str = Field("gpt-5-mini-2025-08-07", validation_alias=AliasChoices("OPENAI_MODEL_INTENT"))
    hypothesis_review: str = Field("gpt-5-mini-2025-08-07", validation_alias=AliasChoices("OPENAI_MODEL_HYPO_REVIEW"))
    answer_synthesis: str = Field("gpt-5-mini-2025-08-07", validation_alias=AliasChoices("OPENAI_MODEL_ANSWER_SYNTH"))
    enhanced_generation: str = Field("gpt-5-mini-2025-08-07", validation_alias=AliasChoices("OPENAI_MODEL_ENHANCED_GEN"))


class FeaturesSettings(BaseSettings):
    model_config = SettingsConfigDict(env_file='.env', extra='ignore')
    
    use_intent_llm: bool = Field(True, validation_alias=AliasChoices("GIA_USE_INTENT_LLM"))
    enable_llm_review: bool = Field(True, validation_alias=AliasChoices("GIA_ENABLE_LLM_REVIEW"))
    disable_hypo_review: bool = Field(False, validation_alias=AliasChoices("GIA_DISABLE_HYPO_REVIEW"))
    # GPT-5/Responses API options
    use_responses_api_for_gpt5: bool = Field(True, validation_alias=AliasChoices("GIA_GPT5_USE_RESPONSES"))
    gpt5_reasoning_effort: str = Field("low", validation_alias=AliasChoices("GIA_GPT5_REASONING"))  # minimal/low/medium/high
    gpt5_text_verbosity: str = Field("low", validation_alias=AliasChoices("GIA_GPT5_VERBOSITY"))    # low/medium/high
    enable_preambles: bool = Field(False, validation_alias=AliasChoices("GIA_GPT5_PREAMBLES"))


class GenerationSettings(BaseModel):
    basic_questions_per_category: int = 30
    enhanced_questions_per_category: int = 120


class LoggingSettings(BaseModel):
    level: str = "INFO"
    format: str = "%(asctime)s - %(levelname)s - %(message)s"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file='.env', extra='ignore')
    
    api: ApiSettings = Field(default_factory=ApiSettings)
    models: ModelsSettings = Field(default_factory=ModelsSettings)
    features: FeaturesSettings = Field(default_factory=FeaturesSettings)
    generation: GenerationSettings = Field(default_factory=GenerationSettings)
    logging: LoggingSettings = Field(default_factory=LoggingSettings)


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

        # .env 로드
        load_dotenv()

        config_dir = os.environ.get("GIA_CONFIG_DIR", ".")
        env = os.environ.get("GIA_ENV", "")

        # YAML 설정 로드 (환경별 오버레이)
        base_config = self._load_yaml(config_dir, "config.yaml")
        if env:
            env_config = self._load_yaml(config_dir, f"config.{env}.yaml")
            self._deep_update(base_config, env_config)

        # 1) YAML 기반 Settings
        yaml_settings = Settings.model_validate(base_config)
        # 2) .env 기반 Settings
        env_settings = Settings()
        # 3) 병합: YAML을 기본으로, .env 값이 존재하면 덮어쓰기
        merged_settings = yaml_settings.model_copy(update=env_settings.model_dump(exclude_unset=True, exclude_none=True))

        self.settings = merged_settings

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
