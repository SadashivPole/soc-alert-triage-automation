"""Phase 1E unit tests: enrichment provider interface & orchestration.

The internet is never touched here (ARCHITECTURE.md §17: no network access in
unit tests). The suite pins the contract that Phase 2 providers (VirusTotal,
MISP) will implement:

* the offline, disabled-by-default :class:`NoOpEnrichmentProvider`;
* structural conformance to the ``EnrichmentProvider`` protocol;
* deterministic, ordered orchestration with payload merging;
* fail-open behaviour when a provider raises (ARCHITECTURE.md §16);
* ``enrichment_status`` aggregation (skipped / complete / partial / failed).
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

import pytest

from soc_triage.enrichment import (
    IOC,
    EnrichmentChain,
    EnrichmentContext,
    EnrichmentProvider,
    EnrichmentStatus,
    IOCType,
    NoOpEnrichmentProvider,
    ProviderEnrichment,
    extract_iocs,
)
from soc_triage.models.canonical import (
    CanonicalAgent,
    CanonicalAlert,
    CanonicalRule,
    CanonicalSourceEvent,
)

# Synthetic documentation-range data only (SECURITY.md §5).
DOC_IP = "203.0.113.50"
MD5 = "bc478d7a48bfab117da4b9bdcb5aee36"


# ---------------------------------------------------------------------------
# Test doubles
# ---------------------------------------------------------------------------


class FakeProvider:
    """An offline stand-in for a future HTTP-backed provider."""

    def __init__(
        self,
        name: str = "fake",
        *,
        enabled: bool = True,
        payload: dict[str, Any] | None = None,
        types: set[IOCType] | None = None,
        raises: type[Exception] | None = None,
        status: EnrichmentStatus | None = None,
        extra_results: dict[str, dict[str, Any]] | None = None,
    ) -> None:
        self._name = name
        self._enabled = enabled
        self._payload = payload if payload is not None else {"reputation": "clean"}
        self._types = types
        self._raises = raises
        self._status = status
        self._extra_results = extra_results or {}
        self.calls: list[tuple[tuple[str, ...], EnrichmentContext]] = []

    @property
    def name(self) -> str:
        return self._name

    @property
    def enabled(self) -> bool:
        return self._enabled

    def handles(self, ioc: IOC) -> bool:
        return self._types is None or ioc.type in self._types

    def enrich(
        self,
        iocs: tuple[IOC, ...],
        *,
        context: EnrichmentContext,
    ) -> ProviderEnrichment:
        if self._raises is not None:
            raise self._raises(f"{self._name} is unavailable")
        self.calls.append((tuple(ioc.key for ioc in iocs), context))
        results: dict[str, dict[str, Any]] = {
            ioc.key: dict(self._payload, provider=self._name) for ioc in iocs if self.handles(ioc)
        }
        results.update(self._extra_results)
        return ProviderEnrichment(
            provider=self._name,
            status=self._status or EnrichmentStatus.COMPLETE,
            results=results,
            notes=[f"{self._name}: ok"],
        )


def make_iocs() -> list[IOC]:
    """A small, deterministic indicator set (documentation-range values)."""
    return [
        IOC(type=IOCType.IPV4, value=DOC_IP),
        IOC(type=IOCType.MD5, value=MD5),
    ]


def make_alert() -> CanonicalAlert:
    """A canonical alert whose only evidence is one documentation-range IP."""
    return CanonicalAlert(
        alert_id=UUID("3f9d2b1e-5c7a-4a1e-9a2f-0b6d8e4c1a11"),
        source="wazuh",
        received_at=datetime(2026, 8, 29, 10, 15, 30, tzinfo=UTC),
        source_event=CanonicalSourceEvent(
            rule=CanonicalRule(id="5710", level=5, description="sshd: failed login"),
            agent=CanonicalAgent(id="001", name="web-prod-01"),
            location="/var/log/auth.log",
            data={"srcip": DOC_IP},
        ),
    )


def snapshot(iocs: tuple[IOC, ...]) -> list[tuple[str, str, dict[str, Any]]]:
    """Comparable view of indicators (type, value, enrichment payloads)."""
    return [(ioc.type.value, ioc.value, dict(ioc.enrichment)) for ioc in iocs]


# ---------------------------------------------------------------------------
# No-op (offline) provider
# ---------------------------------------------------------------------------


def test_noop_provider_is_disabled_by_default() -> None:
    """An unconfigured integration must never be called (ARCHITECTURE §14)."""
    provider = NoOpEnrichmentProvider()

    assert provider.name == "noop"
    assert provider.enabled is False


def test_noop_provider_can_be_enabled_for_tests() -> None:
    """The enabled flag is honoured by the provider and by the chain."""
    assert NoOpEnrichmentProvider(enabled=True).enabled is True


@pytest.mark.parametrize(
    "provider",
    [NoOpEnrichmentProvider(), FakeProvider()],
    ids=["noop", "fake"],
)
def test_providers_conform_to_the_protocol(provider: Any) -> None:
    """``EnrichmentProvider`` is runtime-checkable (duck-typed contract)."""
    assert isinstance(provider, EnrichmentProvider)


def test_noop_provider_returns_skipped_without_payloads() -> None:
    """The offline provider performs no lookup and attaches no data."""
    iocs = make_iocs()
    result = NoOpEnrichmentProvider(enabled=True).enrich(
        iocs, context=EnrichmentContext(alert_id=UUID(int=1))
    )

    assert result.provider == "noop"
    assert result.status is EnrichmentStatus.SKIPPED
    assert result.results == {}
    assert result.notes and all("no external lookup" in note for note in result.notes)


def test_noop_provider_does_not_mutate_indicators() -> None:
    """Providers return data; they never rewrite their inputs."""
    iocs = make_iocs()
    before = snapshot(tuple(iocs))

    NoOpEnrichmentProvider(enabled=True).enrich(iocs, context=EnrichmentContext())

    assert snapshot(tuple(iocs)) == before


# ---------------------------------------------------------------------------
# Chain: skipping
# ---------------------------------------------------------------------------


def test_chain_without_providers_skips() -> None:
    """No provider configured → enrichment is skipped, indicators unchanged."""
    outcome = EnrichmentChain().enrich(make_iocs())

    assert outcome.status is EnrichmentStatus.SKIPPED
    assert outcome.providers == ()
    assert outcome.iocs == tuple(make_iocs())


def test_chain_skips_disabled_provider() -> None:
    """A disabled provider is recorded but never invoked."""
    provider = FakeProvider(enabled=False)
    outcome = EnrichmentChain([provider]).enrich(make_iocs())

    assert outcome.status is EnrichmentStatus.SKIPPED
    assert provider.calls == []
    assert [p.status for p in outcome.providers] == [EnrichmentStatus.SKIPPED]
    assert outcome.providers[0].notes == ("provider disabled",)
    assert all(ioc.enrichment == {} for ioc in outcome.iocs)


def test_chain_with_offline_noop_provider_enriches_nothing() -> None:
    """The offline default leaves indicators untouched (zero-intel mode)."""
    chain = EnrichmentChain([NoOpEnrichmentProvider(enabled=True)])

    outcome = chain.enrich(make_iocs())

    assert outcome.status is EnrichmentStatus.SKIPPED
    assert snapshot(outcome.iocs) == snapshot(tuple(make_iocs()))
    assert outcome.iocs[0].enrichment == {}


def test_chain_skips_when_alert_has_no_indicators() -> None:
    """Nothing to look up → providers are not called at all."""
    provider = FakeProvider()
    outcome = EnrichmentChain([provider]).enrich([])

    assert outcome.status is EnrichmentStatus.SKIPPED
    assert outcome.iocs == ()
    assert provider.calls == []
    assert outcome.providers[0].notes == ("no indicators to enrich",)


# ---------------------------------------------------------------------------
# Chain: merging, ordering, determinism
# ---------------------------------------------------------------------------


def test_chain_merges_provider_payloads_onto_indicators() -> None:
    """Each provider's payload is stored under its own name."""
    chain = EnrichmentChain([FakeProvider("vt")])

    outcome = chain.enrich(make_iocs())

    assert outcome.status is EnrichmentStatus.COMPLETE
    assert outcome.iocs[0].enrichment == {"vt": {"reputation": "clean", "provider": "vt"}}
    assert outcome.providers[0].enriched == 2


def test_chain_merges_multiple_providers_in_registration_order() -> None:
    """Provider payloads coexist; registration order is execution order."""
    chain = EnrichmentChain([FakeProvider("first"), FakeProvider("second")])

    outcome = chain.enrich(make_iocs())

    assert [p.provider for p in outcome.providers] == ["first", "second"]
    assert set(outcome.iocs[0].enrichment) == {"first", "second"}
    assert outcome.iocs[0].enrichment["first"]["provider"] == "first"
    assert outcome.iocs[0].enrichment["second"]["provider"] == "second"


def test_chain_only_passes_indicators_a_provider_handles() -> None:
    """Providers decide what they handle; unhandled keys are simply absent."""
    chain = EnrichmentChain([FakeProvider("hashes", types={IOCType.MD5})])

    outcome = chain.enrich(make_iocs())

    assert outcome.providers[0].enriched == 1
    ipv4, md5 = outcome.iocs
    assert ipv4.enrichment == {}
    assert md5.enrichment == {"hashes": {"reputation": "clean", "provider": "hashes"}}


def test_chain_ignores_unknown_indicator_keys() -> None:
    """A provider returning data for an indicator it was not given is ignored."""
    provider = FakeProvider(extra_results={"ipv4:192.0.2.99": {"reputation": "malicious"}})

    outcome = EnrichmentChain([provider]).enrich(make_iocs())

    assert outcome.providers[0].enriched == 2  # only known keys applied
    assert all("192.0.2.99" not in ioc.value for ioc in outcome.iocs)


def test_chain_passes_correlation_context_to_providers() -> None:
    """Providers receive the alert context (correlation, not control flow)."""
    provider = FakeProvider()
    context = EnrichmentContext(
        alert_id=UUID("3f9d2b1e-5c7a-4a1e-9a2f-0b6d8e4c1a11"),
        source="wazuh",
        dedupe_group="wazuh:5710:001",
    )

    EnrichmentChain([provider]).enrich(make_iocs(), context=context)

    assert provider.calls[0][1].source == "wazuh"
    assert provider.calls[0][1].alert_id == UUID("3f9d2b1e-5c7a-4a1e-9a2f-0b6d8e4c1a11")
    assert provider.calls[0][1].dedupe_group == "wazuh:5710:001"


def test_chain_normalizes_provider_input_order() -> None:
    """Providers always see indicators sorted by (type, value)."""
    provider = FakeProvider()

    EnrichmentChain([provider]).enrich(list(reversed(make_iocs())))

    assert provider.calls[0][0] == (f"ipv4:{DOC_IP}", f"md5:{MD5}")


def test_chain_is_deterministic() -> None:
    """Repeated runs over the same indicators produce identical outcomes."""
    chain = EnrichmentChain([FakeProvider("a"), FakeProvider("b")])

    first = chain.enrich(make_iocs())
    second = chain.enrich(make_iocs())

    assert snapshot(first.iocs) == snapshot(second.iocs)
    assert [p.model_dump(mode="json") for p in first.providers] == [
        p.model_dump(mode="json") for p in second.providers
    ]
    assert first.status is second.status


def test_chain_does_not_mutate_input_indicators() -> None:
    """The chain returns enriched copies; inputs stay clean."""
    iocs = make_iocs()
    before = snapshot(tuple(iocs))

    EnrichmentChain([FakeProvider("vt")]).enrich(iocs)

    assert snapshot(tuple(iocs)) == before


# ---------------------------------------------------------------------------
# Chain: fail-open behaviour
# ---------------------------------------------------------------------------


def test_chain_fails_open_when_provider_raises() -> None:
    """A provider error must never break ingestion (ARCHITECTURE §16)."""
    chain = EnrichmentChain([FakeProvider("vt", raises=RuntimeError)])

    outcome = chain.enrich(make_iocs())

    assert outcome.status is EnrichmentStatus.FAILED
    assert outcome.iocs == tuple(make_iocs())  # indicators survive untouched
    assert outcome.providers[0].error_type == "RuntimeError"
    assert outcome.providers[0].enriched == 0


def test_chain_reports_partial_when_one_provider_fails() -> None:
    """Mixed outcomes are visible as ``partial``, never as silence."""
    healthy = FakeProvider("cache")
    broken = FakeProvider("vt", raises=TimeoutError)

    outcome = EnrichmentChain([broken, healthy]).enrich(make_iocs())

    assert outcome.status is EnrichmentStatus.PARTIAL
    assert [p.status for p in outcome.providers] == [
        EnrichmentStatus.FAILED,
        EnrichmentStatus.COMPLETE,
    ]
    assert outcome.iocs[0].enrichment == {"cache": {"reputation": "clean", "provider": "cache"}}


def test_chain_continues_after_a_failed_provider() -> None:
    """Failure of one provider does not stop the others."""
    first = FakeProvider("misp", raises=ConnectionError)
    second = FakeProvider("vt")

    outcome = EnrichmentChain([first, second]).enrich(make_iocs())

    assert len(second.calls) == 1
    assert outcome.status is EnrichmentStatus.PARTIAL


def test_chain_honours_provider_reported_status() -> None:
    """A provider may report quota/unavailability without raising."""
    provider = FakeProvider("vt", status=EnrichmentStatus.PARTIAL, payload={})

    outcome = EnrichmentChain([provider]).enrich(make_iocs())

    assert outcome.status is EnrichmentStatus.PARTIAL
    assert outcome.iocs[0].enrichment == {"vt": {"provider": "vt"}}


# ---------------------------------------------------------------------------
# End-to-end (offline): extraction → enrichment
# ---------------------------------------------------------------------------


def test_extracted_indicators_flow_through_the_offline_chain() -> None:
    """Phase 1E walking slice: extract → enrich (no-op) → indicators intact."""
    iocs = extract_iocs(make_alert())
    assert [(ioc.type.value, ioc.value) for ioc in iocs] == [("ipv4", DOC_IP)]

    outcome = EnrichmentChain([NoOpEnrichmentProvider()]).enrich(
        iocs, context=EnrichmentContext(source="wazuh")
    )

    assert outcome.status is EnrichmentStatus.SKIPPED
    assert [(ioc.type.value, ioc.value) for ioc in outcome.iocs] == [("ipv4", DOC_IP)]
    assert outcome.iocs[0].enrichment == {}
    assert outcome.providers[0].notes == ("provider disabled",)


def test_enrichment_status_vocabulary_matches_architecture() -> None:
    """``complete | partial | failed | skipped`` (ARCHITECTURE §5.2, §16)."""
    assert {status.value for status in EnrichmentStatus} == {
        "complete",
        "partial",
        "failed",
        "skipped",
    }
