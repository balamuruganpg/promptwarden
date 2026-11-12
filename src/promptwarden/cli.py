"""Command-line interface.

``scan`` prints the score, flag, categories, and signals, and exits 1 when the
text is flagged. ``train`` fits every row of a corpus. ``eval`` prints
precision, recall, F1, and false-positive rate under the protocol in
:mod:`promptwarden.evaluate`. Usage and data errors exit 2.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import NoReturn

from promptwarden.evaluate import evaluate_corpus, fit_examples, load_corpus
from promptwarden.warden import ScanResult, Warden


class UsageError(Exception):
    """Raised for bad arguments. The CLI prints it and exits 2."""


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        self.print_usage(sys.stderr)
        raise UsageError(message)


def main(argv: Sequence[str] | None = None) -> None:
    """Console-script entry point. The process exit code is the scan result."""

    sys.exit(run(argv))


def run(argv: Sequence[str] | None = None) -> int:
    """Run the CLI and return the exit code without exiting the process."""

    parser = _build_parser()
    try:
        args = parser.parse_args(None if argv is None else list(argv))
        if args.command == "scan":
            return _scan(args)
        if args.command == "train":
            return _train(args)
        if args.command == "eval":
            return _eval(args)
        raise UsageError(f"unknown command {args.command}")
    except UsageError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except (OSError, ValueError, TypeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


def _build_parser() -> _Parser:
    parser = _Parser(prog="promptwarden")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="score one text or one file")
    scan.add_argument("text", nargs="?", help="text to scan")
    scan.add_argument("--file", help="read the text from this file")
    scan.add_argument("--threshold", type=float, default=0.5, help="flag at or above this score")

    train = sub.add_parser("train", help="fit a model on every corpus row")
    train.add_argument("--corpus", required=True, help="JSONL corpus path")
    train.add_argument("--out", required=True, help="where to write the model JSON")

    evaluate = sub.add_parser("eval", help="report precision, recall, F1, and FPR")
    evaluate.add_argument("--corpus", required=True, help="JSONL corpus path")
    evaluate.add_argument(
        "--threshold",
        type=float,
        default=0.5,
        help="flag at or above this score",
    )
    return parser


def _scan(args: argparse.Namespace) -> int:
    if args.file and args.text is not None:
        raise UsageError("pass TEXT or --file, not both")
    if args.file:
        text = Path(args.file).read_text(encoding="utf-8")
    elif args.text is None:
        raise UsageError("scan requires TEXT or --file")
    else:
        text = args.text
    result = Warden(args.threshold).scan(text)
    _print_result(result)
    return 1 if result.flagged else 0


def _train(args: argparse.Namespace) -> int:
    model = fit_examples(load_corpus(args.corpus))
    destination = Path(args.out)
    destination.parent.mkdir(parents=True, exist_ok=True)
    model.save(destination)
    print(f"wrote {destination}")
    return 0


def _eval(args: argparse.Namespace) -> int:
    report = evaluate_corpus(args.corpus, threshold=args.threshold)
    sys.stdout.write(report.as_text())
    return 0


def _print_result(result: ScanResult) -> None:
    categories = ", ".join(result.categories) if result.categories else "(none)"
    signals = ", ".join(result.signals) if result.signals else "(none)"
    print(f"score: {result.score:.6f}")
    print(f"flagged: {'true' if result.flagged else 'false'}")
    print(f"categories: {categories}")
    print(f"signals: {signals}")
