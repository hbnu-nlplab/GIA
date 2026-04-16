"""
test_agents_v3.py
-----------------
agents_v3 파이프라인 단일 항목 테스트.
lab_c 첫 번째 항목 1개를 실행하고 로그 및 결과를 확인한다.
"""

import json
import logging
import sys
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
sys.path.append(str(BASE_DIR))

# ── 로거 설정 (콘솔 출력) ──────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger("agents_v3")

# ── 모델 초기화 ───────────────────────────────────
from agents_v3.model_loader import init_models
logger.info("Initializing models...")
init_models()

# ── 그래프 빌드 ───────────────────────────────────
from agents_v3.main_netconfig import build_graph, ConfigManager, process_item
logger.info("Building LangGraph...")
app = build_graph()

# ── 데이터셋 로드 ──────────────────────────────────
dataset_path = BASE_DIR / "data/original/netconfig2/lab_c/LabC_NCN_Security_L2VPN_30nodes_dataset_batfish_20260325_101814_en.json"
with open(dataset_path, encoding="utf-8") as f:
    loaded = json.load(f)
questions = loaded.get("questions", loaded)

# ── ConfigManager 초기화 ───────────────────────────
configs_dir = BASE_DIR / "data/original/netconfig2/lab_c/configs"
cm = ConfigManager(configs_dir, logger)

# ── 테스트 항목 선택 ───────────────────────────────
# 여러 레벨/타입을 빠르게 확인하기 위해 L1, L2, L3 각 1개씩
def pick_one(level):
    for q in questions:
        if q.get("level") == level and q.get("answer_status") == "OK":
            return q
    return None

targets = []
for lvl in ("L1", "L2", "L3"):
    item = pick_one(lvl)
    if item:
        targets.append(item)
        logger.info("Selected %s: [%s] %s → gold=%s", lvl, item["id"], item["question"][:80], item.get("answer",""))

logger.info("=" * 70)

# ── 실행 ──────────────────────────────────────────
results = []
for i, item in enumerate(targets):
    logger.info("=" * 70)
    logger.info("Running item %d/%d: %s", i+1, len(targets), item["id"])
    res = process_item(app, item, i, len(targets), "netconfig", cm)
    results.append(res)
    logger.info("-" * 70)
    if res:
        logger.info("  GOLD : %s", item.get("answer", ""))
        logger.info("  PRED : %s", res.get("pred", ""))
        logger.info("  STATUS : %s | ROUNDS : %d | DURATION : %.1fs",
                    res.get("final_status",""), res.get("debate2_rounds",0), res.get("duration",0))
    else:
        logger.error("  RESULT: None (error occurred)")

# ── 최종 요약 ──────────────────────────────────────
logger.info("=" * 70)
logger.info("SUMMARY")
for item, res in zip(targets, results):
    if res:
        match = str(item.get("eval_answer","")).strip() == str(res.get("pred","")).strip()
        logger.info("  [%s] %-50s | gold=%-20s | pred=%-20s | %s",
                    item["level"], item["id"],
                    item.get("eval_answer","")[:20],
                    str(res.get("pred",""))[:20],
                    "✓" if match else "✗")
