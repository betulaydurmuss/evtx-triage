"""Command line interface."""

from __future__ import annotations

import time
from dataclasses import asdict
from pathlib import Path
from typing import Annotated, Any, Literal

import typer
from rich.console import Console
from rich.table import Table

from .config import Config, ConfigError, load_config
from .ingest.hayabusa_csv import InputContractError, read_events
from .knowledge.attack import AttackError, load_attack
from .knowledge.dictionary import DictionaryError, load_dictionary
from .knowledge.embedder import EmbeddingError
from .knowledge.guidance import GuidanceError, check_guidance, load_guidance
from .knowledge.retrieval import GuidanceRetriever
from .knowledge.vector_store import GuidanceIndexError, build_index, open_fresh_index, read_index, staleness
from .models import InterpretationOutcome
from .pipeline import make_budget, run_deterministic
from .report.json_report import build_report, write_report
from .report.markdown_report import render_markdown
from .report.terminal import render_terminal
from .tokens import TokenizerError
from .validate import assessment_warnings

app = typer.Typer(add_completion=False, help="Local triage summaries for Hayabusa CSV timelines.")
kb_app = typer.Typer(add_completion=False, help="Inspect and build the knowledge base.")
app.add_typer(kb_app, name="kb")

console = Console(stderr=True)

DEFAULT_CONFIG = Path("config/default.toml")
ConfigOption = Annotated[Path, typer.Option("--config", help="Config file")]


def _load(config_path: Path) -> Config:
    try:
        return load_config(config_path)
    except ConfigError as exc:
        console.print(f"[red]config error[/red]\n{exc}")
        raise typer.Exit(code=2) from exc


def _fail(title: str, exc: Exception) -> typer.Exit:
    console.print(f"[red]{title}[/red]\n{exc}")
    return typer.Exit(code=2)


def selection_summary(config: Config, result: Any) -> dict[str, Any]:
    """What the report says about how many groups reached the model."""
    return {
        "model_min_level": config.selection.model_min_level.value,
        "max_groups_to_model": config.selection.max_groups_to_model,
        "eligible": result.selection.eligible,
        "sent": len(result.selected),
        "not_sent": result.selection.not_sent,
    }


def ensure_models(config: Config, *, chat: bool) -> None:
    """Load cached models into the running server when config allows it (ADR-0001 section 9b)."""
    from .llm.runtime import LoadPolicy, RuntimeNotReady, ensure_model_loaded

    if not config.runtime.auto_load_models:
        return
    policy = LoadPolicy(
        foundry_cli=config.runtime.foundry_cli,
        timeout_seconds=config.runtime.model_load_timeout_seconds,
        max_gpu_used_before_chat_load_mib=config.runtime.max_gpu_used_before_chat_load_mib,
    )
    # Embedding first: it runs on the CPU and does not change GPU memory, so the
    # chat model's GPU check afterwards sees the real picture (ADR-0001 section 7).
    wanted: list[tuple[str, Literal["chat", "embedding"]]] = [
        (config.retrieval.embedding_model_id, "embedding")
    ]
    if chat:
        wanted.append((config.llm.model_id, "chat"))
    for model_id, kind in wanted:
        try:
            ensure_model_loaded(
                config.llm.endpoint,
                model_id,
                kind=kind,
                policy=policy,
                timeout=float(config.llm.timeout_seconds),
                log=lambda message: console.print(f"  {message}"),
            )
        except RuntimeNotReady as exc:
            raise _fail("runtime not ready", exc) from exc


def open_retriever(config: Config) -> GuidanceRetriever:
    """Load the notes and a fresh index, and connect the query embedder."""
    from .llm.embeddings import FoundryEmbedder

    corpus = load_guidance(config.resolve(config.knowledge.guidance_dir))
    index = open_fresh_index(
        config.resolve(config.retrieval.index_path),
        corpus=corpus,
        model_id=config.retrieval.embedding_model_id,
        dim=config.retrieval.embedding_dim,
    )
    embedder = FoundryEmbedder(
        endpoint=config.llm.endpoint,
        model_id=config.retrieval.embedding_model_id,
        timeout_seconds=config.llm.timeout_seconds,
    )
    return GuidanceRetriever(
        corpus=corpus,
        index=index,
        embedder=embedder,
        query_instruction=config.retrieval.query_instruction,
    )


@app.command()
def triage(
    csv_path: Annotated[Path, typer.Argument(metavar="CSV", help="Hayabusa CSV produced with -b")],
    out: Annotated[Path, typer.Option(help="Directory for report.json")] = Path("out"),
    config_path: ConfigOption = DEFAULT_CONFIG,
    no_llm: Annotated[
        bool, typer.Option("--no-llm", help="Skip the chat model; retrieval still runs")
    ] = False,
    output_format: Annotated[
        str, typer.Option("--format", help="Comma separated: terminal, md, json")
    ] = "terminal,json",
    audit: Annotated[
        bool, typer.Option("--audit", help="Add raw prompts, responses and validation results to report.json")
    ] = False,
) -> None:
    """Read a Hayabusa timeline and write a triage report."""
    started = time.monotonic()

    formats = [item.strip() for item in output_format.split(",") if item.strip()]
    unknown = sorted(set(formats) - {"terminal", "md", "json"})
    if unknown:
        raise typer.BadParameter(f"unknown output format(s): {', '.join(unknown)}; use terminal, md or json")
    if not formats:
        raise typer.BadParameter("--format needs at least one of: terminal, md, json")
    if audit and "json" not in formats:
        raise typer.BadParameter("--audit writes into report.json; add json to --format")

    config = _load(config_path)

    from .llm.interpret import PromptError, load_prompt

    try:
        prompt = load_prompt(config.llm.prompt_version)
    except PromptError as exc:
        raise _fail("prompt error", exc) from exc

    try:
        budget = make_budget(config)
    except TokenizerError as exc:
        raise _fail("tokenizer error", exc) from exc

    # Retrieval needs the embedding model even with --no-llm.
    ensure_models(config, chat=not no_llm)

    try:
        retriever = open_retriever(config)
        result = run_deterministic(config, csv_path, retriever=retriever, budget=budget)
    except (DictionaryError, AttackError, GuidanceError) as exc:
        raise _fail("knowledge base error", exc) from exc
    except GuidanceIndexError as exc:
        raise _fail("guidance index error", exc) from exc
    except EmbeddingError as exc:
        raise _fail("embedding error", exc) from exc
    except InputContractError as exc:
        raise _fail("input error", exc) from exc
    except OSError as exc:
        raise _fail(f"cannot read {csv_path}", exc) from exc

    if result.selection.capped:
        console.print(
            f"[yellow]{result.selection.eligible} groups reach {config.selection.model_min_level.value}; "
            f"selection.max_groups_to_model = {config.selection.max_groups_to_model}, so the most severe "
            f"{len(result.selected)} go to the model. The rest are in the report with the deterministic "
            "summary only (report: deterministic.selection.not_sent).[/yellow]"
        )
    elif not no_llm and len(result.selected) > 20:
        console.print(
            f"  {len(result.selected)} groups go to the model; the model takes about 10-60 s per group"
        )

    outcomes: list[InterpretationOutcome] = []
    audit_records: list[Any] = []
    if no_llm:
        outcomes = [
            InterpretationOutcome(
                group_id=group.group_id, status="skipped", reasons=["--no-llm was requested"]
            )
            for group in result.selected
        ]
    elif result.selected:
        from .llm.client import FoundryLocalClient
        from .llm.interpret import interpret_group
        from .llm.runtime import RuntimeNotReady, warm_up

        if config.runtime.warm_up_at_full_budget:
            try:
                tokens = warm_up(
                    config.llm.endpoint,
                    config.llm.model_id,
                    budget,
                    timeout=float(config.llm.timeout_seconds),
                )
                console.print(f"  warm-up at the full input budget: {tokens} tokens")
            except RuntimeNotReady as exc:
                raise _fail("runtime not ready", exc) from exc

        client = FoundryLocalClient(
            endpoint=config.llm.endpoint,
            model_id=config.llm.model_id,
            temperature=config.llm.temperature,
            seed=config.llm.seed,
            max_output_tokens=config.llm.max_output_tokens,
            timeout_seconds=config.llm.timeout_seconds,
        )
        for group in result.selected:
            packed = result.packed_by_group[group.group_id]
            notes = result.guidance_by_group[group.group_id]
            user_prompt = result.user_prompt_by_group[group.group_id]
            console.print(
                f"  interpreting {group.group_id}: {len(packed.included_row_ids)} evidence rows, "
                f"{result.prompt_tokens_by_group[group.group_id]} prompt tokens, "
                f"guidance {', '.join(notes) or 'none'}"
            )
            if user_prompt.neutralized_control_tokens:
                console.print(
                    f"  [yellow]{group.group_id}: {user_prompt.neutralized_control_tokens} chat control "
                    "token(s) in the log data were defused[/yellow]"
                )
            interpret_started = time.monotonic()
            outcome = interpret_group(
                client,
                group,
                packed,
                context=result.context_by_group[group.group_id],
                user_prompt=user_prompt,
                prompt=prompt,
                budget=budget,
                max_retries=config.llm.max_retries,
                audit=audit_records if audit else None,
            )
            warnings = assessment_warnings(
                outcome,
                group,
                min_level=config.assessment_check.min_level,
                assessments=config.assessment_check.assessments,
                neutralized_control_tokens=user_prompt.neutralized_control_tokens,
            )
            outcomes.append(
                outcome.model_copy(
                    update={
                        "warnings": warnings,
                        "duration_seconds": round(time.monotonic() - interpret_started, 3),
                    }
                )
            )

    report = build_report(
        config=config,
        config_path=config_path,
        input_path=csv_path,
        ingest=result.ingest,
        groups=result.groups,
        selected_ids=result.selected_ids,
        selection=selection_summary(config, result),
        packed_by_group=result.packed_by_group,
        outcomes=outcomes,
        unknown_pairs=result.unknown_pairs,
        unknown_tactics=result.unknown_tactics,
        unknown_techniques=result.unknown_techniques,
        dictionary_entries=len(result.dictionary),
        knowledge_hash=result.knowledge_hash,
        attack_version=result.attack.version,
        llm_enabled=not no_llm,
        duration_seconds=time.monotonic() - started,
        retrieved_by_group=result.retrieved_by_group,
        retrieval_provenance=result.retrieval_provenance,
        prompt_sha256=prompt.sha256,
        audit=[asdict(record) for record in audit_records] if audit else None,
        prompt_tokens_by_group=result.prompt_tokens_by_group,
        neutralized_by_group={
            gid: user.neutralized_control_tokens for gid, user in result.user_prompt_by_group.items()
        },
        token_provenance=result.token_provenance,
    )
    written: list[Path] = []
    if "json" in formats:
        written.append(write_report(report, out))
    if "md" in formats:
        out.mkdir(parents=True, exist_ok=True)
        markdown_path = out / "report.md"
        markdown_path.write_text(render_markdown(report), encoding="utf-8", newline="\n")
        written.append(markdown_path)
    if "terminal" in formats:
        render_terminal(report, console)

    for path in written:
        console.print(f"[green]{path}[/green]")
    console.print(
        f"rows={result.ingest.data_rows} parsed={len(result.ingest.events)} "
        f"errors={len(result.ingest.errors)} groups={len(result.groups)} "
        f"selected={len(result.selected)}"
    )


@app.command()
def doctor(config_path: ConfigOption = DEFAULT_CONFIG) -> None:
    """Check that the local runtime, models, tokenizer, prompt and knowledge base are ready.

    Sends two one-token probe requests to the loopback endpoint: `/v1/models` lists
    cached models, so a request is the only way to learn whether one is loaded.
    """
    from .llm import runtime
    from .llm.interpret import PromptError, load_prompt
    from .llm.runtime import Check

    config = _load(config_path)
    checks: list[Check] = [Check("config", "ok", f"{config_path} (hash {config.hash()[:12]})")]

    try:
        prompt = load_prompt(config.llm.prompt_version)
        checks.append(
            Check("prompt", "ok", f"{prompt.version} sha256 {prompt.sha256[:12]} matches its release")
        )
    except PromptError as exc:
        checks.append(Check("prompt", "fail", str(exc)))

    tokenizer = runtime.check_tokenizer_file(
        config.resolve(config.llm.tokenizer_file), config.llm.model_id, config.pack.token_counter
    )
    checks.append(tokenizer)
    budget = None
    try:
        budget = make_budget(config)
    except TokenizerError as exc:
        if tokenizer.status != "fail":
            checks.append(Check("tokenizer", "fail", str(exc).replace("\n", " ")))

    try:
        dictionary = load_dictionary(config.resolve(config.knowledge.eventids_dir))
        attack = load_attack(config.resolve(config.knowledge.attack_dir))
        corpus = load_guidance(config.resolve(config.knowledge.guidance_dir))
        checked = check_guidance(corpus, attack, dictionary)
        checks.append(
            Check(
                "knowledge base",
                "fail" if checked.errors else "ok",
                f"{len(dictionary)} dictionary entries, {len(corpus.notes)} guidance notes, "
                f"ATT&CK {attack.version}"
                + (f"; {len(checked.errors)} errors, run: evtx-triage kb check" if checked.errors else ""),
            )
        )
        index_path = config.resolve(config.retrieval.index_path)
        try:
            reasons = staleness(
                read_index(index_path),
                corpus=corpus,
                model_id=config.retrieval.embedding_model_id,
                dim=config.retrieval.embedding_dim,
            )
            checks.append(
                Check("guidance index", "fail", "; ".join(reasons) + "; run: evtx-triage kb build")
                if reasons
                else Check("guidance index", "ok", f"fresh: {index_path}")
            )
        except GuidanceIndexError as exc:
            checks.append(Check("guidance index", "fail", str(exc).replace("\n", " ")))
    except (DictionaryError, AttackError, GuidanceError) as exc:
        checks.append(Check("knowledge base", "fail", str(exc).replace("\n", " ")))

    timeout = float(config.llm.timeout_seconds)
    endpoint = runtime.check_endpoint(
        config.llm.endpoint, [config.llm.model_id, config.retrieval.embedding_model_id], timeout=timeout
    )
    checks.append(endpoint)
    checks.append(runtime.check_loopback_listener(config.llm.endpoint))
    if endpoint.status != "fail":
        if budget is not None:
            checks.extend(
                runtime.check_chat_model(config.llm.endpoint, config.llm.model_id, budget, timeout=timeout)
            )
        checks.append(
            runtime.check_embedding_model(
                config.llm.endpoint,
                config.retrieval.embedding_model_id,
                dim=config.retrieval.embedding_dim,
                normalized=config.retrieval.normalized,
                timeout=timeout,
            )
        )
    checks.append(runtime.check_gpu_memory())

    colours = {"ok": "green", "warn": "yellow", "fail": "red"}
    table = Table("check", "status", "detail", title="evtx-triage doctor")
    for check in checks:
        colour = colours[check.status]
        table.add_row(check.name, f"[{colour}]{check.status}[/{colour}]", check.detail)
    console.print(table)
    failed = [check.name for check in checks if check.status == "fail"]
    if failed:
        console.print(f"[red]not ready:[/red] {', '.join(failed)}")
        raise typer.Exit(code=1)
    console.print("[green]ready[/green]")


@kb_app.command("build")
def kb_build(config_path: ConfigOption = DEFAULT_CONFIG) -> None:
    """Embed the guidance notes and (re)write the vector index."""
    from .llm.embeddings import FoundryEmbedder

    config = _load(config_path)
    started = time.monotonic()
    try:
        corpus = load_guidance(config.resolve(config.knowledge.guidance_dir))
        dictionary = load_dictionary(config.resolve(config.knowledge.eventids_dir))
        attack = load_attack(config.resolve(config.knowledge.attack_dir))
    except (GuidanceError, DictionaryError, AttackError) as exc:
        raise _fail("knowledge base error", exc) from exc

    checked = check_guidance(corpus, attack, dictionary)
    if checked.errors:
        console.print("[red]guidance notes have errors; the index was not built[/red]")
        for line in checked.errors:
            console.print(f"  {line}")
        raise typer.Exit(code=2)

    ensure_models(config, chat=False)
    embedder = FoundryEmbedder(
        endpoint=config.llm.endpoint,
        model_id=config.retrieval.embedding_model_id,
        timeout_seconds=config.llm.timeout_seconds,
    )
    path = config.resolve(config.retrieval.index_path)
    try:
        meta = build_index(
            path,
            corpus,
            embedder,
            dim=config.retrieval.embedding_dim,
            batch_size=config.retrieval.embedding_batch_size,
            expect_normalized=config.retrieval.normalized,
        )
    except (EmbeddingError, GuidanceIndexError) as exc:
        raise _fail("index build failed", exc) from exc

    console.print(
        f"[green]{path}[/green]  notes={meta.note_count} model={meta.model_id} dim={meta.dim} "
        f"corpus={meta.corpus_hash[:12]} ({time.monotonic() - started:.1f}s)"
    )


@kb_app.command("check")
def kb_check(
    config_path: ConfigOption = DEFAULT_CONFIG,
    csv_path: Annotated[
        Path | None, typer.Option("--csv", help="Report dictionary coverage against this timeline")
    ] = None,
) -> None:
    """Validate the knowledge base and the guidance index, and optionally measure coverage."""
    config = _load(config_path)
    failed = False

    try:
        dictionary = load_dictionary(config.resolve(config.knowledge.eventids_dir))
        attack = load_attack(config.resolve(config.knowledge.attack_dir))
        corpus = load_guidance(config.resolve(config.knowledge.guidance_dir))
    except (DictionaryError, AttackError, GuidanceError) as exc:
        raise _fail("knowledge base error", exc) from exc

    console.print(
        f"[green]knowledge base OK[/green]  "
        f"dictionary entries={len(dictionary)}  "
        f"tactics={attack.tactic_count}  techniques={attack.technique_count}  "
        f"attack version={attack.version}"
    )
    per_channel: dict[str, int] = {}
    for channel, _ in dictionary.keys:
        per_channel[channel] = per_channel.get(channel, 0) + 1
    for channel in sorted(per_channel):
        console.print(f"  {per_channel[channel]:>3}  {channel}")

    checked = check_guidance(corpus, attack, dictionary)
    colour = "red" if checked.errors else "green"
    console.print(
        f"\n[{colour}]guidance notes: {len(corpus.notes)}[/{colour}]  "
        f"errors={len(checked.errors)} notes={len(checked.notes)}"
    )
    for line in checked.errors:
        console.print(f"  [red]error[/red] {line}")
    for line in checked.notes:
        console.print(f"  [dim]note[/dim]  {line}")
    failed = failed or bool(checked.errors)

    index_path = config.resolve(config.retrieval.index_path)
    try:
        index = read_index(index_path)
        reasons = staleness(
            index,
            corpus=corpus,
            model_id=config.retrieval.embedding_model_id,
            dim=config.retrieval.embedding_dim,
        )
        if reasons:
            failed = True
            console.print(f"[red]guidance index stale[/red] {index_path}")
            for reason in reasons:
                console.print(f"  - {reason}")
            console.print("  rebuild with: evtx-triage kb build")
        else:
            console.print(f"[green]guidance index fresh[/green] {index_path} ({index.meta.note_count} notes)")
    except GuidanceIndexError as exc:
        failed = True
        console.print(f"[red]guidance index unavailable[/red]\n{exc}")

    if csv_path is not None:
        try:
            ingested = read_events(csv_path, assume_utc=config.ingest.assume_utc)
        except InputContractError as exc:
            raise _fail("input error", exc) from exc

        seen: dict[tuple[str, int], int] = {}
        for event in ingested.events:
            key = (event.channel, event.event_id)
            seen[key] = seen.get(key, 0) + 1
        covered = {key: count for key, count in seen.items() if dictionary.lookup(*key) is not None}
        missing = {key: count for key, count in seen.items() if dictionary.lookup(*key) is None}
        total = sum(seen.values())
        rows_covered = sum(covered.values())
        console.print(
            f"\ncoverage of {csv_path.name}: {len(covered)}/{len(seen)} pairs, "
            f"{rows_covered}/{total} rows ({100 * rows_covered / max(total, 1):.1f}%)"
        )
        if missing:
            failed = True
            table = Table("rows", "channel", "event id", title="uncovered pairs")
            for (channel, event_id), count in sorted(missing.items(), key=lambda item: -item[1]):
                table.add_row(str(count), channel, str(event_id))
            console.print(table)

    if failed:
        raise typer.Exit(code=1)


if __name__ == "__main__":
    app()
