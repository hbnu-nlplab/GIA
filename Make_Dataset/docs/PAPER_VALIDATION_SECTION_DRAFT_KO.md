# 논문용 Validation 섹션 초안

## Ground-Truth Validation

본 연구에서는 단일 oracle의 정확성을 전제하지 않고, 다층 검증 파이프라인을 통해 ground truth의 신뢰성을 확보하였다. 검증 전략은 질문 난이도에 따라 분리되었다.

우선 `L1-L3` 문제는 장비 설정 텍스트에서 직접 유도 가능한 사실 추출 문제이므로, Batfish와 독립적인 Python 기반 config parser를 사용하여 전수 검증하였다. 즉 데이터셋 생성기와 별도로 구현된 독립 parser가 동일한 metric과 scope에 대해 정답을 다시 계산하도록 하였으며, retained row는 이 독립 재계산 결과와 일치하는 경우에만 유지하였다. 또한 `L1-L3`에 대해서는 계층화 표본을 추출하여 사람이 raw configuration을 직접 읽고 확인하는 추가 검토 절차를 수행하였다.

반면 `L4-L5` 문제는 traceroute, reachability, failure impact, root-cause analysis와 같이 네트워크 의미론과 시뮬레이션 결과에 의존한다. 이를 위해 각 `L4-L5` row에 `metric`, `scope`, `scenario`, `query_contract`, `verification_contract`를 함께 저장하고, 별도의 replay verifier가 이 계약 정보만 사용하여 Batfish 질의를 다시 실행하도록 구성하였다. 이 replay verification은 생성기 내부의 hidden state, snapshot 오염, 일회성 생성 버그가 정답에 반영되는 문제를 방지한다. 따라서 retained `L4-L5` row는 저장된 계약만으로 Batfish 결과가 재현 가능한 경우에 한정된다.

그러나 replay verification은 Batfish 내부 일관성을 검증하는 것이지, Batfish가 실제 네트워크 동작을 완벽히 모델링함을 증명하는 것은 아니다. 이를 보완하기 위해 `L4-L5`의 계층화 표본에 대해 PNETLab 기반 외부 검증을 추가로 수행하였다. 이 단계에서는 실제 Cisco IOS 기반 에뮬레이션 환경에서 ping, traceroute, 인터페이스 shutdown, node failure injection 등을 실행하여 Batfish-derived answer가 실환경 관찰 결과와 일치하는지 확인하였다. 본 외부 검증은 표본 기반이므로 전수 검증으로 해석하지 않으며, Batfish-derived semantics에 대한 external sanity check로 사용하였다.

최종적으로 본 데이터셋은 다음 세 가지 성질을 만족하도록 설계되었다. 첫째, `L1-L3`는 independent parser에 의해 전수 검증된다. 둘째, `L4-L5`는 row-level contract를 이용한 Batfish replay로 전수 검증된다. 셋째, `L4-L5`의 일부 표본은 PNETLab에서 외부 검증된다. 또한 재현 불가능하거나 계약이 불완전한 사례는 quarantine 또는 exclusion 대상으로 처리할 수 있도록 fail-closed 정책을 적용하였다. 따라서 본 연구는 데이터셋이 “절대적으로 오류가 없다”고 주장하기보다, retained row가 계약 기반으로 재현 가능하며 다층 검증을 통과한 고신뢰 ground truth임을 주장한다.

## 짧은 버전

본 연구는 ground truth 생성 결과를 그대로 정답으로 간주하지 않고, `L1-L3`에 대해서는 independent parser 기반 전수 검증을, `L4-L5`에 대해서는 Batfish replay 기반 전수 검증을 수행하였다. 추가로 `L4-L5`의 계층화 표본에 대해 PNETLab 실환경 검증을 수행하여 Batfish-derived semantics와 실제 에뮬레이션 동작의 일치 여부를 확인하였다. 불확실하거나 재현 불가능한 row는 retained set에서 제외할 수 있도록 fail-closed 정책을 적용하였다.

## 영어 초안

We do not assume that a single oracle is infallible. Instead, we employ a layered validation pipeline for ground-truth construction. For `L1-L3`, which are directly derivable from configuration text, we perform exhaustive verification using an independent Python-based config parser that is separate from the Batfish-based generator. For `L4-L5`, which depend on semantic network behavior such as traceroute, reachability, failure impact, and root-cause analysis, each row stores a replayable contract including the metric, scope, scenario, and query parameters. A separate replay verifier re-executes Batfish queries solely from these row-level contracts, ensuring that retained rows are replay-verifiable rather than generator-state dependent. To address the limitation that replay verification only establishes internal consistency with Batfish rather than absolute real-world correctness, we additionally conduct stratified external validation in PNETLab for sampled `L4-L5` instances. In this phase, we reproduce the required probes and failure injections on emulated Cisco IOS nodes and compare observed behavior against the Batfish-derived answers. Consequently, our dataset is best described as contract-verified, replay-verifiable, and externally spot-checked, with unverifiable cases handled in a fail-closed manner.
