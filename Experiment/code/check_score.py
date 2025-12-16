import json
from rouge import Rouge
from nltk.translate.bleu_score import sentence_bleu, SmoothingFunction
from bert_score import score

DATA_PATH = "../data/llm_answer_revised/llm_answer_merged.json"
MODEL_TO_EVAL = "gpt-5-mini"  # 평가할 모델

def load_data():
    with open(DATA_PATH, "r", encoding="utf-8") as f:
        return json.load(f)

# ---------------------------
# ROUGE-1, ROUGE-2, ROUGE-L
# ---------------------------
def eval_rouge(gold_list, pred_list):
    rouge = Rouge()
    scores = rouge.get_scores(pred_list, gold_list)  # list of dicts

    avg_r1 = sum(s["rouge-1"]["f"] for s in scores) / len(scores)
    avg_r2 = sum(s["rouge-2"]["f"] for s in scores) / len(scores)
    avg_rl = sum(s["rouge-l"]["f"] for s in scores) / len(scores)

    return {
        "rouge-1": avg_r1,
        "rouge-2": avg_r2,
        "rouge-l": avg_rl,
    }

# ---------------------------
# BLEU
# ---------------------------
def eval_bleu(gold_list, pred_list):
    smooth_fn = SmoothingFunction().method1
    bleu_scores = []

    for g, p in zip(gold_list, pred_list):
        ref = g.split()
        hyp = p.split()
        bleu = sentence_bleu(
            [ref],
            hyp,
            weights=(0.25, 0.25, 0.25, 0.25),
            smoothing_function=smooth_fn
        )
        bleu_scores.append(bleu)

    avg_bleu = sum(bleu_scores) / len(bleu_scores) if bleu_scores else 0.0
    return avg_bleu


# ---------------------------
# BERTScore
# ---------------------------
def eval_bertscore(gold_list, pred_list):
    if not gold_list or not pred_list:
        return 0.0
    P, R, F1 = score(pred_list, gold_list, lang="en",
                      model_type="bert-base-multilingual-cased", verbose=False)
    return F1.mean().item()


# ---------------------------
# Exact match
# ---------------------------
def eval_exact_match(gold_list, pred_list):
    matches = [1 if g == p else 0 for g, p in zip(gold_list, pred_list)]
    return sum(matches) / len(matches) if matches else 0.0


# ---------------------------
# F1 Score
# ---------------------------
def eval_f1(gold_list, pred_list):
    def f1_score(gold, pred):
        gold_tokens = gold.split()
        pred_tokens = pred.split()

        common = set(gold_tokens) & set(pred_tokens)
        num_common = sum(min(gold_tokens.count(t), pred_tokens.count(t)) for t in common)

        if num_common == 0:
            return 0.0

        precision = num_common / len(pred_tokens)
        recall = num_common / len(gold_tokens)
        return 2 * precision * recall / (precision + recall)

    scores = [f1_score(g, p) for g, p in zip(gold_list, pred_list)]
    return sum(scores) / len(scores) if scores else 0.0

# ---------------------------
# MAIN
# ---------------------------
def main():
    data = load_data()

    gold_list = []
    pred_list = []

    for item in data:
        gold = item.get("gold_answer", "").strip()
        pred = item.get(MODEL_TO_EVAL, "").strip()

        if gold and pred:
            gold_list.append(gold)
            pred_list.append(pred)

    if not gold_list or not pred_list:
        print("[!] 평가할 valid entry가 없습니다.")
        return


    rouge_scores = eval_rouge(gold_list, pred_list)
    bleu_score = eval_bleu(gold_list, pred_list)
    bert_f1 = eval_bertscore(gold_list, pred_list)
    em = eval_exact_match(gold_list, pred_list)
    f1 = eval_f1(gold_list, pred_list)


    print(f"=== Evaluation: {MODEL_TO_EVAL} ===")
    print(f"ROUGE-1: {rouge_scores['rouge-1']:.4f}")
    print(f"ROUGE-2: {rouge_scores['rouge-2']:.4f}")
    print(f"ROUGE-L: {rouge_scores['rouge-l']:.4f}")
    print(f"BLEU:    {bleu_score:.4f}")
    print(f"BERTScore(F1): {bert_f1:.4f}")
    print(f"Exact Match: {em:.4f}")
    print(f"Token F1:    {f1:.4f}")

if __name__ == "__main__":
    main()