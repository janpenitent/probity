# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Janier Rodríguez

"""AwsMonitoringConnector tests — fake transport, no network, no real creds.

The fake routes by the ``X-Amz-Target`` header and returns canned AWS JSON-1.1
responses for CloudTrail (DescribeTrails / GetTrailStatus) and SSM
(DescribeInstancePatchStates). The connector is exercised end to end without a
socket, and the SigV4 signing of the POST body is checked from the headers.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

import pytest

from probity.connectors.aws_monitoring_connector import AwsMonitoringConnector
from probity.connectors.mock_assets import PATCH_KIND
from probity.connectors.mock_siem import LOGGING_KIND
from probity.controls.c03_logging import C03Logging
from probity.controls.c14_patch_management import C14PatchManagement
from probity.model.enums import Status
from probity.model.fact import FactSet

_NOW = datetime(2026, 6, 4, 12, 0, 0, tzinfo=UTC)
_FRESH = datetime(2026, 6, 4, 11, 0, 0, tzinfo=UTC).timestamp()  # 1h ago
_STALE = datetime(2026, 1, 1, 0, 0, 0, tzinfo=UTC).timestamp()  # months ago

# CloudTrail trails keyed by Name; value is the GetTrailStatus payload.
_DEFAULT_TRAILS: dict[str, dict[str, Any]] = {
    "org-trail": {"IsLogging": True, "LatestDeliveryTime": _FRESH},
    "audit": {"IsLogging": False, "LatestDeliveryTime": _FRESH},
}

_DEFAULT_PATCH_STATES: list[dict[str, Any]] = [
    {
        "InstanceId": "i-aaa",
        "CriticalNonCompliantCount": 0,
        "SecurityNonCompliantCount": 0,
        "OperationEndTime": _FRESH,
    },
    {
        "InstanceId": "i-bbb",
        "CriticalNonCompliantCount": 2,
        "SecurityNonCompliantCount": 0,
        "OperationEndTime": _FRESH,
    },
    {"OperationEndTime": _FRESH},  # no InstanceId -> skipped
]


def _fake_transport(
    *,
    trails: dict[str, dict[str, Any]] | None = None,
    patch_states: list[dict[str, Any]] | None = None,
    captured: list[dict[str, str]] | None = None,
) -> Any:
    trails = _DEFAULT_TRAILS if trails is None else trails
    patch_states = _DEFAULT_PATCH_STATES if patch_states is None else patch_states

    def transport(method: str, url: str, headers: dict[str, str], body: bytes) -> bytes:
        if captured is not None:
            captured.append(headers)
        target = headers["X-Amz-Target"]
        if target.endswith("DescribeTrails"):
            trail_list = [
                {"Name": name, "TrailARN": f"arn:aws:cloudtrail:eu-west-1:111:trail/{name}"}
                for name in trails
            ]
            return json.dumps({"trailList": trail_list}).encode("utf-8")
        if target.endswith("GetTrailStatus"):
            name = json.loads(body)["Name"].rsplit("/", 1)[-1]
            return json.dumps(trails[name]).encode("utf-8")
        if target.endswith("DescribeInstancePatchStates"):
            return json.dumps({"InstancePatchStates": patch_states}).encode("utf-8")
        raise AssertionError(f"unexpected target: {target}")

    return transport


def _connector(**kw: Any) -> AwsMonitoringConnector:
    transport = kw.pop("transport", None) or _fake_transport()
    return AwsMonitoringConnector(
        access_key="AKIATESTKEY",
        secret_key="secret",
        region="eu-west-1",
        transport=transport,
        now=lambda: _NOW,
        **kw,
    )


def _facts(**kw: Any) -> FactSet:
    return FactSet(tuple(_connector(**kw).collect()))


# -- C03 / CloudTrail ----------------------------------------------------


def test_emits_one_logging_source_per_trail():
    sources = _facts().of_kind(LOGGING_KIND)
    assert [s.data["asset"] for s in sources] == ["org-trail", "audit"]


def test_logging_source_maps_arn_and_forwarding():
    sources = {s.data["asset"]: s for s in _facts().of_kind(LOGGING_KIND)}
    org = sources["org-trail"]
    assert org.data["id"] == "arn:aws:cloudtrail:eu-west-1:111:trail/org-trail"
    assert org.data["critical"] is True
    assert org.data["forwarding"] is True
    assert org.data["last_event"] == datetime.fromtimestamp(_FRESH, UTC).isoformat()
    assert sources["audit"].data["forwarding"] is False


def test_missing_delivery_time_is_none():
    trails = {"t": {"IsLogging": True}}  # no LatestDeliveryTime
    src = _facts(transport=_fake_transport(trails=trails)).of_kind(LOGGING_KIND)[0]
    assert src.data["last_event"] is None


def test_feeds_c03_fail_on_non_forwarding_trail():
    finding = C03Logging(now=_NOW).evaluate(_facts())
    # audit trail is not forwarding -> 1 of 2 critical assets has a gap.
    assert finding.status is Status.FAIL
    assert "1 of 2" in finding.summary


def test_feeds_c03_pass_when_all_trails_forward_fresh():
    trails = {"org-trail": {"IsLogging": True, "LatestDeliveryTime": _FRESH}}
    finding = C03Logging(now=_NOW).evaluate(_facts(transport=_fake_transport(trails=trails)))
    assert finding.status is Status.PASS


# -- C14 / SSM -----------------------------------------------------------


def test_emits_one_patch_host_per_instance_with_id():
    hosts = _facts().of_kind(PATCH_KIND)
    # The third state has no InstanceId and is skipped.
    assert [h.data["id"] for h in hosts] == ["i-aaa", "i-bbb"]


def test_patch_host_maps_counts_and_timestamp():
    hosts = {h.data["id"]: h for h in _facts().of_kind(PATCH_KIND)}
    assert hosts["i-aaa"].data == {
        "id": "i-aaa",
        "host": "i-aaa",
        "critical": True,
        "last_patched": datetime.fromtimestamp(_FRESH, UTC).isoformat(),
        "pending_critical": 0,
    }
    assert hosts["i-bbb"].data["pending_critical"] == 2


def test_feeds_c14_fail_on_pending_critical_patch():
    finding = C14PatchManagement(now=_NOW).evaluate(_facts())
    # i-bbb has 2 pending critical -> 1 of 2 critical hosts behind.
    assert finding.status is Status.FAIL
    assert "1 of 2" in finding.summary


def test_feeds_c14_pass_when_clean_and_fresh():
    states = [
        {
            "InstanceId": "i-aaa",
            "CriticalNonCompliantCount": 0,
            "SecurityNonCompliantCount": 0,
            "OperationEndTime": _FRESH,
        }
    ]
    finding = C14PatchManagement(now=_NOW).evaluate(
        _facts(transport=_fake_transport(patch_states=states))
    )
    assert finding.status is Status.PASS


def test_pagination_follows_next_token():
    pages = [
        {"InstancePatchStates": [{"InstanceId": "i-1"}], "NextToken": "more"},
        {"InstancePatchStates": [{"InstanceId": "i-2"}]},
    ]

    def transport(method: str, url: str, headers: dict[str, str], body: bytes) -> bytes:
        target = headers["X-Amz-Target"]
        if target.endswith("DescribeTrails"):
            return json.dumps({"trailList": []}).encode("utf-8")
        if target.endswith("DescribeInstancePatchStates"):
            return json.dumps(pages.pop(0)).encode("utf-8")
        raise AssertionError(target)

    hosts = _facts(transport=transport).of_kind(PATCH_KIND)
    assert [h.data["id"] for h in hosts] == ["i-1", "i-2"]


# -- SigV4 / JSON protocol ----------------------------------------------


def test_signs_post_with_json_protocol_headers():
    captured: list[dict[str, str]] = []
    list(_connector(transport=_fake_transport(captured=captured)).collect())
    first = captured[0]
    assert first["Content-Type"] == "application/x-amz-json-1.1"
    assert first["X-Amz-Target"].endswith("DescribeTrails")
    assert first["x-amz-date"] == "20260604T120000Z"
    assert "/eu-west-1/cloudtrail/aws4_request" in first["Authorization"]


def test_ssm_call_signed_for_ssm_service():
    captured: list[dict[str, str]] = []
    list(_connector(transport=_fake_transport(captured=captured)).collect())
    ssm = next(h for h in captured if h["X-Amz-Target"].endswith("DescribeInstancePatchStates"))
    assert "/eu-west-1/ssm/aws4_request" in ssm["Authorization"]


def test_session_token_is_signed_and_sent():
    captured: list[dict[str, str]] = []
    conn = AwsMonitoringConnector(
        access_key="AKIATESTKEY",
        secret_key="secret",
        region="eu-west-1",
        session_token="FwoTOKEN",
        transport=_fake_transport(captured=captured),
        now=lambda: _NOW,
    )
    list(conn.collect())
    assert captured[0]["x-amz-security-token"] == "FwoTOKEN"
    assert "x-amz-security-token" in captured[0]["Authorization"]


def test_constructor_requires_credentials():
    with pytest.raises(ValueError, match="requires access_key"):
        AwsMonitoringConnector(access_key="", secret_key="s", region="r")
