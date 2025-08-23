from inspectors.evaluation_system import ComprehensiveEvaluator

def test_evaluate_dataset_uses_answer_type():
    evaluator = ComprehensiveEvaluator()
    predictions = [
        {
            "predicted": "42",
            "ground_truth": "42",
            "question_id": "q1",
            "answer_type": "short",
        },
        {
            "predicted": "This response contains enough words to be treated as a long answer for the evaluator.",
            "ground_truth": "This response contains enough words to be treated as a long answer for the evaluator.",
            "question_id": "q2",
            "answer_type": "long",
        },
    ]
    result = evaluator.evaluate_dataset(predictions)
    individual = result["individual_results"]
    short_res = next(r for r in individual if r["question_id"] == "q1")
    long_res = next(r for r in individual if r["question_id"] == "q2")
    assert short_res.get("token_accuracy") is not None
    assert long_res.get("bleu_score") is not None
