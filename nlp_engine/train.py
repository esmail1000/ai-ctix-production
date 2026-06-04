"""Train the upgraded CTI token-classification model.

Production-level training script for Cyber Threat Intelligence NER.

Features:
- Expanded CTI BIO schema from labels.py.
- Rebuilds dataset from processed reports and regex-assisted weak labels.
- Class-weighted loss to reduce the dominance of the O label.
- Optional focal loss for highly imbalanced NER data.
- Early stopping, gradient accumulation, checkpoint resume.
- Safe fp16/bf16 handling based on hardware.
- Saves model.safetensors, optimizer.pt, scheduler.pt.
- Saves label_map.json, training_config.json, data_profile.json,
  test_metrics.json, and final_eval_report.json.
"""

from __future__ import annotations

import argparse
import inspect
import os
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from labels import ENTITY_TYPES, ID2LABEL, LABEL2ID, LABELS
from preprocessing import (build_dataset_dict, load_processed_reports,
                           train_val_test_split)
from utils import set_seed, write_json

try:
    import evaluate  # type: ignore
    import numpy as np  # type: ignore
    import torch  # type: ignore
    from torch import nn  # type: ignore
    from transformers import AutoConfig  # type: ignore
    from transformers import (AutoModelForTokenClassification, AutoTokenizer,
                              DataCollatorForTokenClassification,
                              EarlyStoppingCallback, Trainer,
                              TrainingArguments)
except ImportError:
    evaluate = None  # type: ignore
    np = None  # type: ignore
    torch = None  # type: ignore
    nn = None  # type: ignore
    AutoConfig = None  # type: ignore
    AutoModelForTokenClassification = None  # type: ignore
    AutoTokenizer = None  # type: ignore
    DataCollatorForTokenClassification = None  # type: ignore
    EarlyStoppingCallback = None  # type: ignore
    Trainer = None  # type: ignore
    TrainingArguments = None  # type: ignore


IGNORE_INDEX = -100


def _require_training_deps() -> None:
    missing: List[str] = []

    if evaluate is None:
        missing.append("evaluate")
    if np is None:
        missing.append("numpy")
    if torch is None or nn is None:
        missing.append("torch")
    if AutoTokenizer is None or AutoModelForTokenClassification is None:
        missing.append("transformers")
    if Trainer is None or TrainingArguments is None or DataCollatorForTokenClassification is None:
        missing.append("transformers[trainer]")

    if missing:
        raise ImportError(
            "Training dependencies are missing: "
            + ", ".join(sorted(set(missing)))
            + ". Install them with: pip install -r requirements.txt"
        )


def _make_json_safe(obj: Any) -> Any:
    """Convert numpy/torch/path objects into JSON-serializable Python values."""
    if obj is None or isinstance(obj, (str, int, float, bool)):
        return obj

    if isinstance(obj, Path):
        return str(obj)

    if np is not None:
        if isinstance(obj, np.generic):
            return obj.item()

        if isinstance(obj, np.ndarray):
            return obj.tolist()

    if torch is not None and hasattr(torch, "Tensor") and isinstance(obj, torch.Tensor):
        return obj.detach().cpu().tolist()

    if isinstance(obj, dict):
        return {str(_make_json_safe(k)): _make_json_safe(v) for k, v in obj.items()}

    if isinstance(obj, (list, tuple, set)):
        return [_make_json_safe(v) for v in obj]

    return str(obj)


def _to_jsonable_namespace(args: argparse.Namespace) -> Dict[str, Any]:
    return _make_json_safe(vars(args))


def _labels_to_seqeval(
    predictions: Any,
    labels: Any,
) -> Tuple[List[List[str]], List[List[str]]]:
    if np is None:
        raise ImportError("numpy is required for metrics.")

    pred_ids = np.argmax(predictions, axis=-1)

    true_preds: List[List[str]] = []
    true_labs: List[List[str]] = []

    for pred_row, lab_row in zip(pred_ids, labels):
        p_chunks: List[str] = []
        l_chunks: List[str] = []

        for p, l in zip(pred_row, lab_row):
            if int(l) == IGNORE_INDEX:
                continue

            p_chunks.append(ID2LABEL.get(int(p), "O"))
            l_chunks.append(ID2LABEL.get(int(l), "O"))

        true_preds.append(p_chunks)
        true_labs.append(l_chunks)

    return true_preds, true_labs


def _build_compute_metrics():
    if evaluate is None or np is None:
        raise ImportError("Metric computation requires evaluate and numpy.")

    metric = evaluate.load("seqeval")

    def compute_metrics(eval_pred: Tuple[Any, Any]) -> Dict[str, float]:
        predictions, labels = eval_pred
        true_preds, true_labs = _labels_to_seqeval(predictions, labels)

        results: Dict[str, Any] = metric.compute(
            predictions=true_preds,
            references=true_labs,
            zero_division=0,
        )

        return {
            "precision": float(results.get("overall_precision", 0.0)),
            "recall": float(results.get("overall_recall", 0.0)),
            "f1": float(results.get("overall_f1", 0.0)),
            "accuracy": float(results.get("overall_accuracy", 0.0)),
        }

    return compute_metrics


def _full_seqeval_report(predictions: Any, labels: Any) -> Dict[str, Any]:
    if evaluate is None:
        raise ImportError("evaluate is required for final reports.")

    metric = evaluate.load("seqeval")
    true_preds, true_labs = _labels_to_seqeval(predictions, labels)

    return metric.compute(
        predictions=true_preds,
        references=true_labs,
        zero_division=0,
    )


def _dataset_label_counter(dataset_split: Any) -> Counter:
    counter: Counter = Counter()

    for row in dataset_split:
        for label_id in row.get("labels", []):
            label_id = int(label_id)

            if label_id == IGNORE_INDEX:
                continue

            label_name = ID2LABEL.get(label_id, "UNKNOWN")
            counter[label_name] += 1

    return counter


def _build_data_profile(dataset: Any) -> Dict[str, Any]:
    profile: Dict[str, Any] = {
        "num_labels": len(LABELS),
        "num_entity_types": len(ENTITY_TYPES),
        "splits": {},
    }

    for split_name in dataset.keys():
        counter = _dataset_label_counter(dataset[split_name])
        total = sum(counter.values())
        non_o = total - counter.get("O", 0)

        profile["splits"][split_name] = {
            "rows": len(dataset[split_name]),
            "token_labels_total": total,
            "entity_token_labels": non_o,
            "o_token_labels": counter.get("O", 0),
            "entity_token_ratio": float(non_o / total) if total else 0.0,
            "labels_present": dict(sorted(counter.items())),
            "entity_types_present": sorted(
                {
                    label_name[2:]
                    for label_name, count in counter.items()
                    if count > 0 and label_name.startswith(("B-", "I-"))
                }
            ),
        }

    return profile


def _compute_class_weights(
    train_dataset: Any,
    mode: str,
    max_weight: float,
    o_label_weight: float,
) -> Optional[Any]:
    if mode == "none":
        return None

    if np is None or torch is None:
        raise ImportError("class weights require numpy and torch.")

    counts = np.ones(len(LABELS), dtype=np.float64)

    for row in train_dataset:
        for label_id in row.get("labels", []):
            label_id = int(label_id)

            if label_id == IGNORE_INDEX:
                continue

            if 0 <= label_id < len(counts):
                counts[label_id] += 1.0

    total = float(counts.sum())
    weights = total / (len(counts) * counts)

    if mode == "sqrt":
        weights = np.sqrt(weights)
    elif mode == "balanced":
        pass
    else:
        raise ValueError("--class_weighting must be one of: none, sqrt, balanced")

    weights = weights / max(float(weights.mean()), 1e-12)
    weights = np.clip(weights, 0.05, max_weight)

    if "O" in LABEL2ID:
        weights[LABEL2ID["O"]] = min(weights[LABEL2ID["O"]], o_label_weight)

    return torch.tensor(weights, dtype=torch.float32)


def _hardware_profile() -> Dict[str, Any]:
    if torch is None:
        return {"torch_available": False}

    has_cuda = torch.cuda.is_available()

    profile: Dict[str, Any] = {
        "torch_available": True,
        "cuda_available": has_cuda,
        "cuda_device_count": torch.cuda.device_count() if has_cuda else 0,
        "device": "cuda" if has_cuda else "cpu",
    }

    if has_cuda:
        profile["cuda_device_name"] = torch.cuda.get_device_name(0)
        profile["bf16_supported"] = bool(torch.cuda.is_bf16_supported())

    return profile


def _sanitize_precision_flags(args: argparse.Namespace) -> None:
    if torch is None:
        args.fp16 = False
        args.bf16 = False
        return

    if not torch.cuda.is_available():
        if args.fp16 or args.bf16:
            print("Warning: fp16/bf16 requested but CUDA is not available. Disabling mixed precision.")
        args.fp16 = False
        args.bf16 = False
        return

    if args.fp16 and args.bf16:
        print("Warning: both fp16 and bf16 were requested. Using bf16 if supported, otherwise fp16.")
        if torch.cuda.is_bf16_supported():
            args.fp16 = False
        else:
            args.bf16 = False

    if args.bf16 and not torch.cuda.is_bf16_supported():
        print("Warning: bf16 requested but not supported by this GPU. Falling back to fp16.")
        args.bf16 = False
        args.fp16 = True


def _training_args_kwargs(args: argparse.Namespace) -> Dict[str, Any]:
    if TrainingArguments is None:
        raise ImportError("TrainingArguments is unavailable. Install transformers.")

    signature = inspect.signature(TrainingArguments.__init__)  # type: ignore[attr-defined]
    parameters = signature.parameters

    kwargs: Dict[str, Any] = {
        "output_dir": str(args.output_dir),
        "overwrite_output_dir": args.overwrite_output_dir,
        "learning_rate": args.lr,
        "per_device_train_batch_size": args.batch_size,
        "per_device_eval_batch_size": args.eval_batch_size or args.batch_size,
        "gradient_accumulation_steps": args.gradient_accumulation_steps,
        "num_train_epochs": args.epochs,
        "weight_decay": args.weight_decay,
        "max_grad_norm": args.max_grad_norm,
        "lr_scheduler_type": args.lr_scheduler_type,
        "save_strategy": args.save_strategy,
        "load_best_model_at_end": True,
        "metric_for_best_model": "f1",
        "greater_is_better": True,
        "logging_steps": args.logging_steps,
        "save_total_limit": args.save_total_limit,
        "report_to": [],
        "seed": args.seed,
        "data_seed": args.seed,
        "fp16": args.fp16,
        "bf16": args.bf16,
        "save_safetensors": True,
        "dataloader_num_workers": args.dataloader_num_workers,
        "disable_tqdm": args.disable_tqdm,
    }

    if args.warmup_steps > 0:
        kwargs["warmup_steps"] = args.warmup_steps
    else:
        kwargs["warmup_ratio"] = args.warmup_ratio

    if args.optim:
        kwargs["optim"] = args.optim

    if args.eval_strategy == "epoch":
        if "evaluation_strategy" in parameters:
            kwargs["evaluation_strategy"] = "epoch"
        elif "eval_strategy" in parameters:
            kwargs["eval_strategy"] = "epoch"
    else:
        if "evaluation_strategy" in parameters:
            kwargs["evaluation_strategy"] = "steps"
        elif "eval_strategy" in parameters:
            kwargs["eval_strategy"] = "steps"
        kwargs["eval_steps"] = args.eval_steps
        kwargs["save_steps"] = args.save_steps or args.eval_steps

    return {key: value for key, value in kwargs.items() if key in parameters}


def _build_callbacks(args: argparse.Namespace) -> List[Any]:
    callbacks: List[Any] = []

    if args.early_stopping_patience > 0:
        if EarlyStoppingCallback is None:
            raise ImportError("EarlyStoppingCallback unavailable. Install/update transformers.")

        callbacks.append(
            EarlyStoppingCallback(
                early_stopping_patience=args.early_stopping_patience,
                early_stopping_threshold=args.early_stopping_threshold,
            )
        )

    return callbacks


def _focal_loss(
    logits: Any,
    labels: Any,
    class_weights: Optional[Any],
    gamma: float,
    label_smoothing: float,
) -> Any:
    if nn is None or torch is None:
        raise ImportError("focal loss requires torch.")

    num_labels = logits.shape[-1]
    flat_logits = logits.view(-1, num_labels)
    flat_labels = labels.view(-1)

    valid_mask = flat_labels != IGNORE_INDEX

    if valid_mask.sum() == 0:
        return flat_logits.sum() * 0.0

    flat_logits = flat_logits[valid_mask]
    flat_labels = flat_labels[valid_mask]

    weights = class_weights.to(logits.device) if class_weights is not None else None

    ce = nn.CrossEntropyLoss(
        weight=weights,
        reduction="none",
        label_smoothing=label_smoothing,
    )(flat_logits, flat_labels)

    pt = torch.exp(-ce)
    loss = ((1.0 - pt) ** gamma) * ce

    return loss.mean()


def _cross_entropy_loss(
    logits: Any,
    labels: Any,
    class_weights: Optional[Any],
    label_smoothing: float,
) -> Any:
    if nn is None:
        raise ImportError("cross entropy requires torch.")

    weights = class_weights.to(logits.device) if class_weights is not None else None

    loss_fct = nn.CrossEntropyLoss(
        weight=weights,
        ignore_index=IGNORE_INDEX,
        label_smoothing=label_smoothing,
    )

    return loss_fct(logits.view(-1, logits.shape[-1]), labels.view(-1))


def _build_trainer(
    model: Any,
    training_args: Any,
    dataset: Any,
    tokenizer: Any,
    data_collator: Any,
    class_weights: Optional[Any],
    callbacks: Sequence[Any],
    loss_type: str,
    focal_gamma: float,
    label_smoothing: float,
) -> Any:
    if Trainer is None:
        raise ImportError("Trainer is unavailable. Install requirements.txt.")

    trainer_signature = inspect.signature(Trainer.__init__)  # type: ignore[attr-defined]
    trainer_parameters = trainer_signature.parameters

    trainer_kwargs: Dict[str, Any] = {
        "model": model,
        "args": training_args,
        "train_dataset": dataset["train"],
        "eval_dataset": dataset["validation"],
        "data_collator": data_collator,
        "compute_metrics": _build_compute_metrics(),
        "callbacks": list(callbacks),
    }

    if "processing_class" in trainer_parameters:
        trainer_kwargs["processing_class"] = tokenizer
    elif "tokenizer" in trainer_parameters:
        trainer_kwargs["tokenizer"] = tokenizer

    use_custom_loss = class_weights is not None or loss_type == "focal" or label_smoothing > 0.0

    if not use_custom_loss:
        return Trainer(**trainer_kwargs)  # type: ignore[operator]

    class CTITrainer(Trainer):  # type: ignore[misc, valid-type]
        def __init__(
            self,
            *trainer_args: Any,
            class_weights_tensor: Optional[Any],
            configured_loss_type: str,
            configured_focal_gamma: float,
            configured_label_smoothing: float,
            **trainer_kwargs_inner: Any,
        ) -> None:
            super().__init__(*trainer_args, **trainer_kwargs_inner)
            self.class_weights_tensor = class_weights_tensor
            self.configured_loss_type = configured_loss_type
            self.configured_focal_gamma = configured_focal_gamma
            self.configured_label_smoothing = configured_label_smoothing

        def compute_loss(
            self,
            model: Any,
            inputs: Dict[str, Any],
            return_outputs: bool = False,
            **_: Any,
        ) -> Any:
            labels = inputs.pop("labels")
            outputs = model(**inputs)
            logits = outputs.get("logits") if isinstance(outputs, dict) else outputs.logits

            if self.configured_loss_type == "focal":
                loss = _focal_loss(
                    logits,
                    labels,
                    self.class_weights_tensor,
                    self.configured_focal_gamma,
                    self.configured_label_smoothing,
                )
            else:
                loss = _cross_entropy_loss(
                    logits,
                    labels,
                    self.class_weights_tensor,
                    self.configured_label_smoothing,
                )

            return (loss, outputs) if return_outputs else loss

    return CTITrainer(
        **trainer_kwargs,
        class_weights_tensor=class_weights,
        configured_loss_type=loss_type,
        configured_focal_gamma=focal_gamma,
        configured_label_smoothing=label_smoothing,
    )


def _save_optimizer_and_scheduler(trainer: Any, output_dir: Path) -> None:
    if torch is None:
        return

    optimizer = getattr(trainer, "optimizer", None)
    scheduler = getattr(trainer, "lr_scheduler", None)

    if optimizer is not None:
        torch.save(optimizer.state_dict(), output_dir / "optimizer.pt")

    if scheduler is not None:
        torch.save(scheduler.state_dict(), output_dir / "scheduler.pt")


def _latest_checkpoint(output_dir: Path) -> Optional[str]:
    if not output_dir.exists():
        return None

    checkpoints = [p for p in output_dir.glob("checkpoint-*") if p.is_dir()]

    if not checkpoints:
        return None

    checkpoints.sort(
        key=lambda p: int(p.name.split("-")[-1]) if p.name.split("-")[-1].isdigit() else -1
    )

    return str(checkpoints[-1])


def _validate_dataset(dataset: Any) -> None:
    if len(dataset["train"]) == 0:
        raise RuntimeError("Training split is empty.")

    if len(dataset["validation"]) == 0:
        raise RuntimeError("Validation split is empty.")

    train_profile = _build_data_profile(dataset)["splits"]["train"]

    if train_profile["entity_token_labels"] == 0:
        raise RuntimeError(
            "Training split contains no entity labels. Check preprocessing/coverage report."
        )


def _load_or_build_dataset(args: argparse.Namespace, tokenizer: Any) -> Any:
    if args.load_dataset and args.processed_dataset_dir.exists():
        from datasets import DatasetDict  # type: ignore

        return DatasetDict.load_from_disk(str(args.processed_dataset_dir))

    examples = load_processed_reports(
        args.processed_json,
        raw_text_dir=args.raw_text_dir,
        raw_pdf_dir=args.raw_pdf_dir,
        allow_synthetic_fallback=args.allow_synthetic_fallback,
        fuzzy_threshold=args.fuzzy_threshold,
        coverage_report_path=args.coverage_report,
        use_regex=not args.no_regex_labels,
    )

    if not examples:
        raise RuntimeError(
            "No training examples produced. Add raw .txt reports under --raw_text_dir, "
            "extract PDFs with prepare_data.py, or use --allow_synthetic_fallback for smoke testing. "
            f"See coverage report: {args.coverage_report}"
        )

    train_ex, val_ex, test_ex = train_val_test_split(examples, args.seed)

    dataset = build_dataset_dict(
        train_ex,
        val_ex,
        test_ex,
        tokenizer,
        args.max_length,
        stride=args.stride,
    )

    if args.save_dataset:
        args.processed_dataset_dir.parent.mkdir(parents=True, exist_ok=True)
        dataset.save_to_disk(str(args.processed_dataset_dir))

    return dataset


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Train CTI/SecBERT token classifier for cyber NER.")

    p.add_argument("--processed_json", type=Path, required=True)
    p.add_argument("--raw_text_dir", type=Path, default=Path("data/raw"))
    p.add_argument("--raw_pdf_dir", type=Path, default=None)
    p.add_argument("--allow_synthetic_fallback", action="store_true")
    p.add_argument("--fuzzy_threshold", type=float, default=0.88)
    p.add_argument("--no_regex_labels", action="store_true")
    p.add_argument("--coverage_report", type=Path, default=Path("data/processed/coverage_report_v2.json"))

    p.add_argument("--output_dir", type=Path, default=Path("models/cyberbert-ner-v3"))
    p.add_argument("--processed_dataset_dir", type=Path, default=Path("data/processed/dataset_v3"))
    p.add_argument("--save_dataset", action="store_true")
    p.add_argument("--load_dataset", action="store_true")
    p.add_argument("--overwrite_output_dir", action="store_true")

    p.add_argument("--model_name", type=str, default="jackaduma/SecBERT")
    p.add_argument("--resume_from_checkpoint", type=Path, default=None)
    p.add_argument("--auto_resume", action="store_true")

    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--max_length", type=int, default=512)
    p.add_argument("--stride", type=int, default=64)

    p.add_argument("--batch_size", type=int, default=8)
    p.add_argument("--eval_batch_size", type=int, default=None)
    p.add_argument("--gradient_accumulation_steps", type=int, default=1)

    p.add_argument("--epochs", type=float, default=8.0)
    p.add_argument("--lr", type=float, default=2e-5)
    p.add_argument("--weight_decay", type=float, default=0.01)
    p.add_argument("--warmup_ratio", type=float, default=0.06)
    p.add_argument("--warmup_steps", type=int, default=0)
    p.add_argument("--max_grad_norm", type=float, default=1.0)
    p.add_argument("--lr_scheduler_type", type=str, default="linear")
    p.add_argument("--optim", type=str, default=None)

    p.add_argument("--loss_type", choices=("cross_entropy", "focal"), default="focal")
    p.add_argument("--focal_gamma", type=float, default=2.0)
    p.add_argument("--label_smoothing", type=float, default=0.0)
    p.add_argument("--class_weighting", choices=("none", "sqrt", "balanced"), default="sqrt")
    p.add_argument("--max_class_weight", type=float, default=8.0)
    p.add_argument("--o_label_weight", type=float, default=0.35)

    p.add_argument("--eval_strategy", choices=("epoch", "steps"), default="epoch")
    p.add_argument("--save_strategy", choices=("epoch", "steps"), default="epoch")
    p.add_argument("--eval_steps", type=int, default=100)
    p.add_argument("--save_steps", type=int, default=None)

    p.add_argument("--early_stopping_patience", type=int, default=3)
    p.add_argument("--early_stopping_threshold", type=float, default=0.0)
    p.add_argument("--logging_steps", type=int, default=25)
    p.add_argument("--save_total_limit", type=int, default=3)
    p.add_argument("--dataloader_num_workers", type=int, default=0)
    p.add_argument("--disable_tqdm", action="store_true")

    p.add_argument("--fp16", action="store_true")
    p.add_argument("--bf16", action="store_true")

    return p.parse_args()


def main() -> None:
    _require_training_deps()

    args = parse_args()
    _sanitize_precision_flags(args)

    set_seed(args.seed)
    os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")

    args.output_dir.mkdir(parents=True, exist_ok=True)

    tokenizer = AutoTokenizer.from_pretrained(
        args.model_name,
        use_fast=True,
    )
    label2id = dict(LABEL2ID)
    id2label = {int(k): v for k, v in ID2LABEL.items()}

    if AutoConfig is not None:
        config = AutoConfig.from_pretrained(args.model_name)
        config.num_labels = len(LABELS)
        config.id2label = id2label
        config.label2id = label2id
        config.problem_type = "single_label_classification"

        model = AutoModelForTokenClassification.from_pretrained(
            args.model_name,
            config=config,
            ignore_mismatched_sizes=True,
        )
    else:
        model = AutoModelForTokenClassification.from_pretrained(
            args.model_name,
            num_labels=len(LABELS),
            id2label=id2label,
            label2id=label2id,
            ignore_mismatched_sizes=True,
        )
    dataset = _load_or_build_dataset(args, tokenizer)
    _validate_dataset(dataset)

    data_profile = _build_data_profile(dataset)
    write_json(args.output_dir / "data_profile.json", _make_json_safe(data_profile))

    data_collator = DataCollatorForTokenClassification(tokenizer)
    training_args = TrainingArguments(**_training_args_kwargs(args))

    class_weights = _compute_class_weights(
        dataset["train"],
        args.class_weighting,
        args.max_class_weight,
        args.o_label_weight,
    )

    if class_weights is not None:
        write_json(
            args.output_dir / "class_weights.json",
            _make_json_safe(
                {
                    ID2LABEL[i]: float(class_weights[i].item())
                    for i in range(len(LABELS))
                }
            ),
        )

    trainer = _build_trainer(
        model=model,
        training_args=training_args,
        dataset=dataset,
        tokenizer=tokenizer,
        data_collator=data_collator,
        class_weights=class_weights,
        callbacks=_build_callbacks(args),
        loss_type=args.loss_type,
        focal_gamma=args.focal_gamma,
        label_smoothing=args.label_smoothing,
    )

    resume_checkpoint: Optional[str] = str(args.resume_from_checkpoint) if args.resume_from_checkpoint else None

    if args.auto_resume and resume_checkpoint is None:
        resume_checkpoint = _latest_checkpoint(args.output_dir)

    train_result = trainer.train(resume_from_checkpoint=resume_checkpoint)

    trainer.save_model(str(args.output_dir))
    tokenizer.save_pretrained(str(args.output_dir))
    trainer.save_state()
    _save_optimizer_and_scheduler(trainer, args.output_dir)

    eval_split = "test" if len(dataset["test"]) > 0 else "validation"

    metrics = trainer.evaluate(dataset[eval_split])
    write_json(args.output_dir / "test_metrics.json", _make_json_safe(metrics))

    prediction_output = trainer.predict(dataset[eval_split])
    final_report = _full_seqeval_report(
        prediction_output.predictions,
        prediction_output.label_ids,
    )

    write_json(args.output_dir / "final_eval_report.json", _make_json_safe(final_report))

    write_json(
        args.output_dir / "label_map.json",
        _make_json_safe(
            {
                "schema_version": "3.0",
                "entity_types": list(ENTITY_TYPES),
                "labels": LABELS,
                "label2id": LABEL2ID,
                "id2label": {str(k): v for k, v in ID2LABEL.items()},
            }
        ),
    )

    write_json(
        args.output_dir / "training_config.json",
        _make_json_safe(
            {
                "args": _to_jsonable_namespace(args),
                "hardware": _hardware_profile(),
                "num_labels": len(LABELS),
                "num_entity_types": len(ENTITY_TYPES),
                "train_rows": len(dataset["train"]),
                "validation_rows": len(dataset["validation"]),
                "test_rows": len(dataset["test"]),
                "resume_from_checkpoint": resume_checkpoint,
                "train_metrics": train_result.metrics,
                "eval_split": eval_split,
                "final_metrics": metrics,
            }
        ),
    )

    print("Training complete.")
    print(f"Model saved to: {args.output_dir}")
    print(f"Evaluation split: {eval_split}")
    print(_make_json_safe(metrics))


if __name__ == "__main__":
    try:
        main()
    except ImportError as exc:
        import sys

        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1) from None