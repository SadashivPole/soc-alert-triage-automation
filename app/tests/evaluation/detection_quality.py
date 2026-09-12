from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class DetectionQualityThresholds:
    minimum_precision: float = 1.0
    minimum_recall: float = 11 / 12
    minimum_f1: float = 22 / 23
    maximum_false_positive_rate: float = 0.0
    minimum_true_positive: int = 11
    maximum_false_positive: int = 0
    maximum_false_negative: int = 1
    minimum_true_negative: int = 12


DETECTION_QUALITY_THRESHOLDS = DetectionQualityThresholds()


def assert_detection_quality_gate(metrics: dict[str, float | int]) -> None:
    thresholds = DETECTION_QUALITY_THRESHOLDS

    assert metrics["precision"] >= thresholds.minimum_precision, (
        f"precision {metrics['precision']:.10f} "
        f"is below minimum {thresholds.minimum_precision:.10f}"
    )
    assert metrics["recall"] >= thresholds.minimum_recall, (
        f"recall {metrics['recall']:.10f} "
        f"is below minimum {thresholds.minimum_recall:.10f}"
    )
    assert metrics["f1"] >= thresholds.minimum_f1, (
        f"f1 {metrics['f1']:.10f} "
        f"is below minimum {thresholds.minimum_f1:.10f}"
    )
    assert metrics["false_positive_rate"] <= thresholds.maximum_false_positive_rate, (
        f"false_positive_rate {metrics['false_positive_rate']:.10f} "
        f"exceeds maximum {thresholds.maximum_false_positive_rate:.10f}"
    )

    assert metrics["true_positive"] >= thresholds.minimum_true_positive, (
        f"true_positive {metrics['true_positive']} "
        f"is below minimum {thresholds.minimum_true_positive}"
    )
    assert metrics["false_positive"] <= thresholds.maximum_false_positive, (
        f"false_positive {metrics['false_positive']} "
        f"exceeds maximum {thresholds.maximum_false_positive}"
    )
    assert metrics["false_negative"] <= thresholds.maximum_false_negative, (
        f"false_negative {metrics['false_negative']} "
        f"exceeds maximum {thresholds.maximum_false_negative}"
    )
    assert metrics["true_negative"] >= thresholds.minimum_true_negative, (
        f"true_negative {metrics['true_negative']} "
        f"is below minimum {thresholds.minimum_true_negative}"
    )


def format_detection_quality(metrics: dict[str, float | int]) -> str:
    return (
        f"TP={metrics['true_positive']} "
        f"FP={metrics['false_positive']} "
        f"FN={metrics['false_negative']} "
        f"TN={metrics['true_negative']} "
        f"precision={metrics['precision']:.4f} "
        f"recall={metrics['recall']:.4f} "
        f"f1={metrics['f1']:.4f} "
        f"fpr={metrics['false_positive_rate']:.4f}"
    )
