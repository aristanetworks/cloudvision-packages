# Copyright (c) 2026 Arista Networks, Inc.
# Use of this source code is governed by the Apache License 2.0
# that can be found in the COPYING file.

"""Stateful baseline-aware Enter BGP Maintenance Mode action.

The baseline is stored in EOS maintenance comments.
"""

import base64
import json
import re
import time
import zlib

from cloudvision.cvlib import ActionFailed


ALIAS_PREFIX = "cvp_stateful_bgp_mm"
ALIAS_RE = re.compile(
    r"(?:^|\s)(?:alias\s+)?(%s_(\d+)_(\d+))\s*(?:=|:)??\s+([A-Za-z0-9_-]+)" %
    re.escape(ALIAS_PREFIX)
)
MARKER_CHUNK_SIZE = 900
DEFAULT_MAINTENANCE_ENTRY_TIMEOUT = 300
MIN_MAINTENANCE_ENTRY_TIMEOUT = 30
MAX_MAINTENANCE_ENTRY_TIMEOUT = 900


def _fail(message):
    raise ActionFailed(message)


def _run(ctx, commands):
    responses = ctx.runDeviceCmds(commands)
    errors = [response.get("error") for response in responses
              if isinstance(response, dict) and response.get("error")]
    if errors:
        _fail("Command failed: " + str(errors[0]))
    return responses


def _payload(response):
    if not isinstance(response, dict):
        return {}
    value = response.get("response", response)
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except (TypeError, ValueError):
            return {"output": value}
    # Depending on the EOS command and cvlib response path, structured output
    # may be returned as either a mapping or a list of command records.  Keep
    # both forms so alias readback can inspect either representation.
    return value if isinstance(value, (dict, list)) else {}


def _alias_text(value, parent=""):
    """Return strings and key/value renderings from running-config JSON."""
    found = []
    if isinstance(value, dict):
        for key, child in value.items():
            prefix = (parent + " " + str(key)).strip()
            # Some EOS JSON responses store a complete CLI command in the
            # map key and use null as its value.
            found.append(prefix)
            if isinstance(child, (str, int, float)):
                found.append("%s %s" % (prefix, child))
            found.extend(_alias_text(child, prefix))
    elif isinstance(value, list):
        for child in value:
            if isinstance(child, str) and parent:
                found.append("%s %s" % (parent, child))
            found.extend(_alias_text(child, parent))
    elif isinstance(value, str):
        found.append(value)
    return found


def _read_markers(ctx):
    markers = []
    responses = _run(ctx, [
        "enable",
        "show running-config",
        "show running-config | section alias",
    ])
    for response in responses:
        for text in _alias_text(_payload(response)):
            for match in ALIAS_RE.finditer(text):
                markers.append({
                    "name": match.group(1),
                    "index": int(match.group(2)),
                    "total": int(match.group(3)),
                    "chunk": match.group(4),
                })
    return markers


def _read_bgp(ctx):
    response = _run(ctx, ["show ip bgp summary vrf all"])[0]
    vrfs = _payload(response).get("vrfs", {})
    if not isinstance(vrfs, dict):
        _fail("BGP summary did not contain a valid vrfs object")

    peers = {}
    for vrf, vrf_data in vrfs.items():
        if not isinstance(vrf_data, dict):
            _fail("BGP summary contained invalid data for VRF " + str(vrf))
        peer_data = vrf_data.get("peers", {})
        if not isinstance(peer_data, dict):
            _fail("BGP summary contained invalid peers for VRF " + str(vrf))
        for peer, status in peer_data.items():
            if not isinstance(status, dict) or "peerState" not in status:
                _fail("BGP peer state is missing for %s/%s" % (vrf, peer))
            peers["%s|%s" % (vrf, peer)] = {
                "vrf": str(vrf),
                "peer": str(peer),
                "established": str(status["peerState"]).lower() == "established",
            }
    return peers


def _encode_markers(baseline):
    payload = zlib.compress(
        json.dumps(baseline, separators=(",", ":"), sort_keys=True).encode("utf-8"),
        level=9,
    )
    encoded = base64.urlsafe_b64encode(payload).decode("ascii").rstrip("=")
    chunks = [encoded[i:i + MARKER_CHUNK_SIZE]
              for i in range(0, len(encoded), MARKER_CHUNK_SIZE)] or [""]
    total = len(chunks)
    return [{
        "name": "%s_%d_%d" % (ALIAS_PREFIX, index, total),
        "index": index,
        "total": total,
        "chunk": chunk,
    } for index, chunk in enumerate(chunks, 1)]


def _config_args(ctx):
    action = getattr(ctx, "action", None)
    args = getattr(action, "args", {}) if action else {}
    return args if isinstance(args, dict) else {}


def _maintenance_entry_timeout(ctx):
    raw = _config_args(ctx).get(
        "MaintenanceEntryTimeoutSeconds", DEFAULT_MAINTENANCE_ENTRY_TIMEOUT
    )
    if raw is None or str(raw).strip() == "":
        raw = DEFAULT_MAINTENANCE_ENTRY_TIMEOUT
    try:
        timeout = int(str(raw).strip())
    except (TypeError, ValueError):
        _fail("MaintenanceEntryTimeoutSeconds must be an integer number of seconds")
    if not MIN_MAINTENANCE_ENTRY_TIMEOUT <= timeout <= MAX_MAINTENANCE_ENTRY_TIMEOUT:
        _fail("MaintenanceEntryTimeoutSeconds must be between %d and %d seconds" %
              (MIN_MAINTENANCE_ENTRY_TIMEOUT, MAX_MAINTENANCE_ENTRY_TIMEOUT))
    return timeout


def _maintenance(ctx):
    response = _run(ctx, ["show maintenance"])[0]
    units = _payload(response).get("units", {})
    system = units.get("System", {}) if isinstance(units, dict) else {}
    return system if isinstance(system, dict) else {}


def _check_enter_health(ctx):
    """Wait for EOS to finish entering maintenance mode.

    EOS 4.35 can report ``maintenanceModeEnter`` for several seconds after
    the configuration commit.  The built-in action waits for this transition;
    checking only once creates a false failure even though the unit is still
    progressing normally.
    """
    last_state = None
    pending_peers = []
    timeout_seconds = _maintenance_entry_timeout(ctx)
    attempts = max(1, (timeout_seconds + 1) // 2)
    ctx.info("Waiting up to %d seconds for System to enter maintenance mode." %
             timeout_seconds)
    for attempt in range(attempts):
        system = _maintenance(ctx)
        state = system.get("state", system.get("adminState"))
        previous_state = last_state
        last_state = state
        if state != previous_state:
            ctx.info("Enter maintenance state: " + str(state))
        elif attempt and attempt % 15 == 0:
            ctx.info("Still waiting for maintenance entry; elapsed seconds: %d" %
                     (attempt * 2))
        if state not in ("maintenanceModeEnter", "underMaintenance"):
            _fail("unit System did not enter maintenance mode: " + str(state))

        if state == "underMaintenance":
            if system.get("intfsViolatingTrafficThreshold", False):
                _fail("unit System traffic violates the maintenance threshold")

            peers = _read_bgp(ctx)
            # The built-in action requires all visible peers to acknowledge
            # maintenance.  They can lag the unit state, so poll them too.
            response = _run(ctx, ["show ip bgp summary vrf all"])[0]
            vrfs = _payload(response).get("vrfs", {})
            pending_peers = [
                "%s/%s" % (peer, vrf)
                for vrf, vrf_data in vrfs.items()
                for peer, status in vrf_data.get("peers", {}).items()
                if not status.get("underMaintenance", False)
            ]
            if not pending_peers:
                return peers

        if attempt < attempts - 1:
            time.sleep(2)

    if pending_peers:
        _fail("Peers did not enter maintenance mode: " + str(pending_peers))
    _fail("unit System did not enter maintenance mode within %d seconds: %s" %
          (timeout_seconds, last_state))


args = _config_args(ctx)
ctx.info("Enter Stateful BGP Maintenance Mode started.")
existing_markers = _read_markers(ctx)
if existing_markers:
    # More than one marker means a previous run could not be unambiguously
    # associated with this action.  Do not risk using the wrong baseline.
    totals = {marker["total"] for marker in existing_markers}
    if len(totals) != 1:
        _fail("Multiple or incomplete Stateful BGP baseline markers already exist")
    ctx.info("Found %d existing baseline marker record(s); replacing them." %
             len(existing_markers))
else:
    ctx.info("No existing Stateful BGP baseline marker found.")

baseline = {
    "version": 1,
    "change_control": args.get("ChangeControlID", args.get("CCID", "unknown")),
    "peers": _read_bgp(ctx),
}
established_count = sum(1 for peer in baseline["peers"].values()
                        if peer["established"])
ctx.info("Captured BGP baseline: %d peer(s), %d Established, %d already down." %
         (len(baseline["peers"]), established_count,
          len(baseline["peers"]) - established_count))
markers = _encode_markers(baseline)

ctx.info("Writing %d baseline marker chunk(s) to the device." % len(markers))
commands = ["enable", "configure session"]
commands.extend("no alias " + marker["name"] for marker in existing_markers)
commands.extend("alias %s %s" % (marker["name"], marker["chunk"])
                for marker in markers)
commands.append("maintenance")
commands.extend([
    "unit System",
    "quiesce",
    "commit",
])
_run(ctx, commands)
ctx.info("Maintenance configuration committed; saving startup configuration.")
# Save after commit so the alias baseline survives an EOS reboot/upgrade.
_run(ctx, ["enable", "copy running-config startup-config"])
expected_markers = {(marker["name"], marker["chunk"]) for marker in markers}
marker_saved = False
for attempt in range(10):
    written_markers = _read_markers(ctx)
    actual_markers = {(marker["name"], marker["chunk"]) for marker in written_markers}
    if expected_markers.issubset(actual_markers):
        marker_saved = True
        ctx.info("Baseline marker readback succeeded on attempt %d." % (attempt + 1))
        break
    if attempt < 9:
        time.sleep(2)
if not marker_saved:
    ctx.info(
        "Marker readback did not find the expected alias after 20 seconds; "
        "observed marker names: {}".format(
            sorted({marker["name"] for marker in written_markers})
        )
    )
    _fail("Stateful BGP baseline marker was not readable after commit/save")
_check_enter_health(ctx)
ctx.info("Enter Stateful BGP Maintenance Mode completed successfully.")
