---
trigger: always_on
---

# Experiment Tracking & Analysis Standards

**Activation:** Always applied during experiment execution and logging

---

## 1. 실험 기록 필수 항목 (Mandatory Metadata)

모든 실험 로그는 나중에 논문의 **Methodology**와 **Result** 섹션으로 즉시 변환될 수 있도록 아래 항목을 반드시 포함해야 합니다.

- **Experiment ID:** `[Exp-YYYYMMDD-순번]` (예: Exp-20251224-01)
- **Environment:** - Git Commit Hash: `$(git rev-parse HEAD)`
  - Hardware: 사용된 GPU 모델 및 개수 (예: RTX 4090 x 2)
  - Key Libraries: PyTorch, CUDA 버전 등 핵심 종속성
- **Dataset:** 데이터셋 버전, 전처리 옵션, Train/Val/Test Split 비율

---

## 2. 수식 및 데이터 표기 원칙

논문 작성 시 오타를 방지하고 일관성을 유지하기 위해 수식과 지표는 다음 규격을 따릅니다.

- **Mathematical Formulas:** 모든 수식은 LaTeX 형식인 `$$ $$`를 사용하여 작성합니다.
  - 예: $$L_{total} = \lambda L_{task} + (1-\lambda) L_{reg}$$
- **Metric Precision:** 주요 지표(Accuracy, F1, Loss 등)는 소수점 4자리까지 기록함을 원칙으로 합니다.
- **Statistical Significance:** 가급적 3회 이상의 실험(Seed 변경 등)을 수행하고 평균($$\mu$$)과 표준편차($$\sigma$$)를 함께 기록합니다.

---

## 3. 분석 및 시각화 (Analysis & Visualization)

단순 수치 나열을 넘어, 에이전트는 다음과 같은 심층 분석을 제공해야 합니다.

- **Ablation Study:** 특정 모듈이나 하이퍼파라미터가 결과에 미친 영향을 정량적으로 분석합니다.
- **Error Analysis:** 모델이 실패한 Case를 샘플링하여 패턴을 분석하고 Markdown 리스트로 정리합니다.
- **Artifacts:** 생성된 `loss_curve.png`, `confusion_matrix.pdf` 등의 결과물 경로를 상대 경로로 링크합니다.

---

## 4. 에이전트 워크플로우 (Agent Action)

1. **Pre-experiment:** 실험 시작 전, 현재 설정(config)이 기존 실험들과 어떻게 다른지 요약하여 사용자에게 확인을 받습니다.
2. **Post-experiment:** 실험이 끝나면 자동으로 `EXPERIMENTS.md`에 위 서식대로 로그를 추가하고, 이전 최고 성능(SOTA) 대비 변화를 보고합니다.
3. **Drafting:** 사용자가 "논문 결과 섹션 써줘"라고 요청하면, `EXPERIMENTS.md`에 기록된 표와 수치를 바탕으로 학술적인 문장으로 초안을 작성합니다.
