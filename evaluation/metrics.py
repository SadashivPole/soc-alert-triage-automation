from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ConfusionMatrix:
    true_positive: int
    false_positive: int
    false_negative: int
    true_negative: int

    @property
    def total(self) -> int:
        return (
            self.true_positive
            + self.false_positive
            + self.false_negative
            + self.true_negative
        )


def calculate_metrics(
    matrix: ConfusionMatrix,
) -> dict[str, float | int]:
    tp = matrix.true_positive
    fp = matrix.false_positive
    fn = matrix.false_negative
    tn = matrix.true_negative

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (
        2 * precision * recall / (precision + recall)
        if (precision + recall)
        else 0.0
    )
    false_positive_rate = (
        fp / (fp + tn)
        if (fp + tn)
        else 0.0
    )

    return {
        "true_positive": tp,
        "false_positive": fp,
        "false_negative": fn,
        "true_negative": tn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "false_positive_rate": false_positive_rate,
    }
