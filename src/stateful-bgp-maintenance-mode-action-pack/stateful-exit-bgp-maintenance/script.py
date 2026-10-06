# Copyright (c) 2026 Arista Networks, Inc.
# Use of this source code is governed by the Apache License 2.0
# that can be found in the COPYING file.

"""Stateful baseline-aware Exit BGP Maintenance Mode action.

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
DEFAULT_PEER_RECOVERY_TIMEOUT = 300
MIN_PEER_RECOVERY_TIMEOUT = 1
MAX_PEER_RECOVERY_TIMEOUT = 900
TRANSITION_ATTEMPTS = 30


def _fail(message):
    raise ActionFailed(message)


def _config_args(ctx):
    action = getattr(ctx, "action", None)
    args = getattr(action, "args", {}) if action else {}
    return args if isinstance(args, dict) else {}


def _peer_recovery_timeout(ctx):
    raw = _config_args(ctx).get(
        "PeerRecoveryTimeoutSeconds", DEFAULT_PEER_RECOVERY_TIMEOUT
    )
    if raw is None or str(raw).strip() == "":
        raw = DEFAULT_PEER_RECOVERY_TIMEOUT
    try:
        timeout = int(str(raw).strip())
    except (TypeError, ValueError):
        _fail("PeerRecoveryTimeoutSeconds must be an integer number of seconds")
    if not MIN_PEER_RECOVERY_TIMEOUT <= timeout <= MAX_PEER_RECOVERY_TIMEOUT:
        _fail("PeerRecoveryTimeoutSeconds must be between %d and %d seconds" %
              (MIN_PEER_RECOVERY_TIMEOUT, MAX_PEER_RECOVERY_TIMEOUT))
    return timeout


def _run(ctx, commands, fmt=None):
    if fmt is None:
        responses = ctx.runDeviceCmds(commands)
    else:
        responses = ctx.runDeviceCmds(commands, fmt=fmt)
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


def _read_marker(ctx):
    commands = [
        "enable",
        "show running-config",
        "show running-config | section alias",
    ]
    responses = _run(ctx, commands)
    candidates = []

    # Do not merge marker records from different EOS command responses.  EOS
    # can return a cached running-config view alongside a current `show
    # aliases` view while a CVaaS configuration transaction is settling.  A
    # merge makes the same marker index look like a conflicting duplicate.
    for command, response in zip(commands, responses):
        pieces = {}
        total = None
        names = {}
        for text in _alias_text(_payload(response)):
            for match in ALIAS_RE.finditer(text):
                name = match.group(1)
                index = int(match.group(2))
                marker_total = int(match.group(3))
                chunk = match.group(4)
                if total is not None and total != marker_total:
                    pieces = {}
                    total = None
                    names = {}
                    break
                total = marker_total
                if index in pieces and pieces[index] != chunk:
                    pieces = {}
                    total = None
                    names = {}
                    break
                pieces[index] = chunk
                names[index] = name
            if total is None and not pieces:
                continue

        if total is not None and set(pieces) == set(range(1, total + 1)):
            candidates.append((command, pieces, names, total))

    if not candidates:
        _fail("Exit stopped safely: the saved BGP baseline was not found or is "
              "incomplete on the switch. Quiesce was not removed. Check the "
              "cvp_stateful_bgp_mm_* aliases and restore the baseline before "
              "retrying Exit.")

    # Prefer the filtered running config, then the full running config.  Do
    # not use `show aliases`: its API representation can be stale or expose an
    # alias value differently from the exact persisted CLI configuration.
    preference = {
        "show running-config | section alias": 0,
        "show running-config": 1,
    }
    decode_errors = []
    for _, pieces, names, total in sorted(
        candidates, key=lambda candidate: preference.get(candidate[0], 99)
    ):
        encoded = "".join(pieces[index] for index in range(1, total + 1))
        try:
            padding = "=" * (-len(encoded) % 4)
            payload = base64.urlsafe_b64decode(encoded + padding)
            payload = zlib.decompress(payload)
            baseline = json.loads(payload.decode("utf-8"))
        except (ValueError, TypeError, UnicodeError, zlib.error, json.JSONDecodeError) as error:
            decode_errors.append(str(error))
            continue
        if baseline.get("version") == 1 and isinstance(baseline.get("peers"), dict):
            return baseline, [names[index] for index in range(1, total + 1)]
        decode_errors.append("unsupported baseline format")

    _fail("Exit stopped safely: the saved BGP baseline on the switch is corrupt. "
          "Quiesce was not removed. Check the cvp_stateful_bgp_mm_* aliases "
          "before retrying Exit. Details: " + decode_errors[0])


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
                "underMaintenance": bool(status.get("underMaintenance", False)),
            }
    return peers


def _maintenance(ctx):
    response = _run(ctx, ["show maintenance"])[0]
    units = _payload(response).get("units", {})
    system = units.get("System", {}) if isinstance(units, dict) else {}
    return system if isinstance(system, dict) else {}


def _maintenance_config(ctx):
    """Return the structured EOS maintenance configuration, if present."""
    responses = _run(ctx, ["enable", "show running-config"])
    for response in responses:
        payload = _payload(response)
        if not isinstance(payload, dict):
            continue
        cmds = payload.get("cmds", {})
        if not isinstance(cmds, dict):
            continue
        maintenance = cmds.get("maintenance")
        if isinstance(maintenance, dict):
            return maintenance
    return None


def _cleanup_maintenance(ctx, markers):
    """Remove only the temporary System maintenance state.

    Preserve unrelated maintenance comments, units, and commands. This
    mirrors the built-in action's cleanup behavior instead of unconditionally
    issuing ``no maintenance``.
    """
    maintenance = _maintenance_config(ctx)
    remove_unit = False
    remove_section = False

    if isinstance(maintenance, dict):
        top_comments = maintenance.get("comments", [])
        top_cmds = maintenance.get("cmds", {})
        if not isinstance(top_comments, list):
            top_comments = [top_comments]
        if not isinstance(top_cmds, dict):
            top_cmds = {}

        unit = top_cmds.get("unit System")
        if isinstance(unit, dict):
            unit_comments = unit.get("comments", [])
            unit_cmds = unit.get("cmds", {})
            if not isinstance(unit_comments, list):
                unit_comments = [unit_comments]
            if not isinstance(unit_cmds, dict):
                unit_cmds = {}

            # The custom action owns quiesce. If that is the only remaining
            # command, the temporary unit can be removed. Preserve the unit
            # if another command or comment belongs to the customer.
            remove_unit = not unit_comments and set(unit_cmds) <= {"quiesce"}

        other_top_cmds = set(top_cmds) - {"unit System"}
        remove_section = all((
            not top_comments,
            not other_top_cmds,
            remove_unit or unit is None,
        ))

    if not isinstance(maintenance, dict):
        ctx.info("Maintenance configuration is already absent; removing markers only.")

    cleanup_commands = ["enable", "configure session"]
    cleanup_commands.extend("no alias " + name for name in markers)
    if remove_unit:
        cleanup_commands.extend(["maintenance", "no unit System"])
    cleanup_commands.append("commit")
    _run(ctx, cleanup_commands)

    if remove_section:
        ctx.info("System maintenance unit was temporary; removing empty maintenance section.")
        _run(ctx, ["enable", "configure session", "no maintenance", "commit"])
    elif isinstance(maintenance, dict):
        ctx.info("Preserved unrelated maintenance configuration while removing temporary state.")


def _wait_for_maintenance(ctx):
    """Wait for an Enter action to finish its EOS state transition."""
    last_state = None
    for attempt in range(TRANSITION_ATTEMPTS):
        system = _maintenance(ctx)
        state = system.get("state", system.get("adminState"))
        last_state = state
        if attempt == 0 or attempt % 5 == 0:
            ctx.info("Waiting for maintenance entry; EOS state: %s" % state)
        if state == "underMaintenance":
            return
        if state != "maintenanceModeEnter":
            _fail("unit System is not under maintenance mode: " + str(state))
        if attempt % 15 == 0 and attempt:
            ctx.info("Still waiting for BGP peer recovery; elapsed seconds: {}".format(
                attempt * 2
            ))
        if attempt < TRANSITION_ATTEMPTS - 1:
            time.sleep(2)
    _fail("unit System did not finish entering maintenance mode: " + str(last_state))


def _wait_for_exit(ctx):
    """Wait for an Exit action to finish its EOS state transition."""
    last_state = None
    for attempt in range(30):
        system = _maintenance(ctx)
        state = system.get("state", system.get("adminState"))
        last_state = state
        if attempt == 0 or attempt % 5 == 0:
            ctx.info("Waiting for maintenance exit; EOS state: %s" % state)
        if state != "underMaintenance" and state != "maintenanceModeExit":
            return
        if attempt < 29:
            time.sleep(2)
    _fail("unit System is still under maintenance mode after exit: " + str(last_state))


def _check_convergence_while_quiesced(ctx, baseline):
    """Check convergence before releasing traffic from maintenance.

    EOS can report a convergence timeout when a peer that was already down at
    Enter remains down. That is the deliberate exception for this custom
    action. A previously-established peer going down, a new down peer, or an
    unaccounted pending peer remains a hard failure.
    """
    response = _run(ctx, ["show bgp convergence vrf all"], fmt="text")[0]
    text = _payload(response).get("output", "")
    if not isinstance(text, str) or not text.strip():
        return False, "BGP convergence returned no text"

    states = [state.strip() for state in re.findall(
        r"B(?:GP|gp) convergence state\s*:\s*(.+)", text)]
    if not states:
        return False, "BGP convergence text contained no recognizable state"

    current = _read_bgp(ctx)
    baseline_down = {key for key, saved in baseline["peers"].items()
                     if not saved.get("established", False)}
    down_after = {key for key, value in current.items()
                  if not value["established"]}
    newly_down = sorted(key for key in down_after
                        if key not in baseline["peers"])
    if newly_down:
        return False, "new or previously unseen peers are down: " + str(newly_down)
    temporarily_down = sorted(
        key for key, value in current.items()
        if all((
            not value["established"],
            baseline["peers"].get(key, {}).get("established", False),
        ))
    )
    temporary_note = ""
    if temporarily_down:
        temporary_note = (
            "; peers currently down while quiesced; waiting for "
            "convergence before removing quiesce: {}".format(temporarily_down)
        )
    pending = [int(value) for value in re.findall(
        r"[Pp]ending [Pp]eers\s*:\s*(\d+)", text)]
    # EOS can report a normal transitional state while it waits for
    # EORs/Keepalives. Treat it as retryable, and allow it to complete only
    # when its pending peers are accounted for by baseline-down peers.
    non_converged = [
        state for state in states
        if all((
            state not in ("Converged", "Timeout reached"),
            not state.startswith("Pending"),
            not state.startswith("Not Initiated"),
        ))
    ]
    if non_converged:
        return False, (
            "BGP convergence returned an unrecognized state: {}{}".format(
                non_converged, temporary_note
            )
        )

    eligible_baseline_down = sorted(
        key for key in baseline_down if key in down_after
    )

    # Not Initiated means EOS has not seen its first peer yet. It is
    # retryable. The only exception is when all currently-down peers are
    # baseline-down peers; in that case there is no previously-established
    # peer waiting to recover before quiesce can be removed.
    if any(state.startswith("Not Initiated") for state in states):
        if eligible_baseline_down and not temporarily_down:
            ctx.info("Allowing Not Initiated convergence state because all "
                     "currently-down peers were already down in the Enter "
                     "baseline: %s" % eligible_baseline_down)
            return True, ("only baseline-down peers remain; allowing "
                          "Not Initiated convergence state" + temporary_note)
        return False, "BGP convergence is still waiting for peers: " + str(states) + temporary_note

    pending_count = sum(pending)
    if all(state == "Converged" for state in states) or pending_count == 0:
        return True, "BGP convergence is complete" + temporary_note

    # A timeout is acceptable only when the pending peers can be accounted for
    # by peers that were already down in the saved baseline. Peers that are
    # temporarily down while quiesced are validated after traffic is released;
    # applying the final peer regression test here would prevent them from
    # recovering after quiesce is removed.
    if pending_count <= len(eligible_baseline_down):
        ctx.info(
            "Allowing {} pending BGP peer(s) because they were already "
            "down in the Enter baseline: {}".format(
                pending_count, eligible_baseline_down
            )
        )
        return True, "only baseline-down peers remain pending" + temporary_note
    return False, (
        "BGP convergence has {} pending peer(s); only {} are accounted for "
        "by baseline-down peers{}".format(
            pending_count, len(eligible_baseline_down), temporary_note
        )
    )


def _wait_for_pre_exit_convergence(ctx, baseline, timeout_seconds):
    """Wait for convergence while quiesce still suppresses forwarding."""
    deadline = time.monotonic() + timeout_seconds
    attempt = 0
    last_reason = "unknown convergence state"
    ctx.info("Starting pre-exit BGP convergence gate while System remains "
             "quiesced; timeout is %d seconds." % timeout_seconds)
    while True:
        attempt += 1
        ready, reason = _check_convergence_while_quiesced(ctx, baseline)
        if attempt == 1 or reason != last_reason or attempt % 15 == 0:
            ctx.info("Pre-exit convergence attempt %d: %s" % (attempt, reason))
        last_reason = reason
        if ready:
            ctx.info("Pre-exit BGP convergence gate passed while traffic "
                     "remains suppressed.")
            return
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            _fail(
                "BGP convergence was not verified before removing quiesce: {}".format(
                    last_reason
                )
            )
        time.sleep(min(2, remaining))


def _check_peer_regression(baseline, current):
    """Apply the baseline-aware peer-down policy independently of CLI text."""
    down_after = {key for key, value in current.items() if not value["established"]}
    unexpected_down = [key for key in down_after
                       if baseline["peers"].get(key, {}).get("established", False)]
    new_down = [key for key in down_after if key not in baseline["peers"]]
    missing_established = [key for key, saved in baseline["peers"].items()
                           if all((
                               saved.get("established"),
                               not current.get(key, {}).get("established", False),
                           ))]
    failures = sorted(set(unexpected_down + new_down + missing_established))
    if failures:
        _fail("BGP peers newly down or missing: " + str(failures))
    return down_after


def _wait_for_peer_recovery(ctx, baseline, timeout_seconds):
    """Wait for peers to return after EOS removes maintenance quiesce."""
    last_unexpected = []
    last_new = []
    last_missing = []
    maintenance_error = ""
    deadline = time.monotonic() + timeout_seconds
    attempt = 0
    ctx.info("Polling BGP peer recovery with a %d-second timeout." % timeout_seconds)
    while True:
        current = _read_bgp(ctx)
        try:
            _check_maintenance_ack(current, False)
            maintenance_error = ""
        except ActionFailed as error:
            maintenance_error = str(error)
        down_after = {key for key, value in current.items()
                      if not value["established"]}
        last_unexpected = [key for key in down_after
                           if baseline["peers"].get(key, {}).get("established", False)]
        last_new = [key for key in down_after if key not in baseline["peers"]]
        last_missing = [key for key, saved in baseline["peers"].items()
                        if all((
                            saved.get("established"),
                            not current.get(key, {}).get("established", False),
                        ))]
        if all((
            not maintenance_error,
            not last_unexpected,
            not last_new,
            not last_missing,
        )):
            ctx.info("BGP peers recovered and no longer acknowledge maintenance.")
            return current
        if attempt and attempt % 15 == 0:
            elapsed = int(time.monotonic() - (deadline - timeout_seconds))
            pending_peers = sorted(
                set(last_unexpected + last_new + last_missing)
            )
            maintenance_status = (
                "; maintenance status: {}".format(maintenance_error)
                if maintenance_error else ""
            )
            ctx.info(
                "Still waiting for BGP peer recovery; elapsed seconds: {}; "
                "pending peers: {}{}".format(
                    elapsed, pending_peers, maintenance_status
                )
            )
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        time.sleep(min(2, remaining))
        attempt += 1
    details = sorted(set(last_unexpected + last_new + last_missing))
    if maintenance_error:
        details.append(maintenance_error)
    _fail("BGP peers did not recover after maintenance: " + str(details))


def _check_maintenance_ack(current, expected):
    for key, peer in current.items():
        if peer["underMaintenance"] != expected:
            if expected:
                _fail("Peer %s for VRF %s is not under maintenance mode" %
                      (peer["peer"], peer["vrf"]))
            _fail("Peer %s for VRF %s is still under maintenance mode" %
                  (peer["peer"], peer["vrf"]))


ctx.info("Exit Stateful BGP Maintenance Mode started.")
baseline, markers = _read_marker(ctx)
established_count = sum(1 for peer in baseline["peers"].values()
                        if peer.get("established"))
ctx.info("Loaded BGP baseline: %d peer(s), %d previously Established." %
         (len(baseline["peers"]), established_count))
peer_recovery_timeout = _peer_recovery_timeout(ctx)
ctx.info("Configured peer recovery timeout: %d seconds." % peer_recovery_timeout)
_wait_for_maintenance(ctx)
current = _read_bgp(ctx)

system = _maintenance(ctx)
state = system.get("state", system.get("adminState"))
if state != "underMaintenance":
    _fail("unit System is not under maintenance mode: " + str(state))

_check_maintenance_ack(current, True)
ctx.info("All visible peers acknowledge maintenance mode.")
_wait_for_pre_exit_convergence(ctx, baseline, peer_recovery_timeout)
ctx.info("Pre-exit convergence passed; removing quiesce and releasing traffic.")
_run(ctx, [
    "enable",
    "configure session",
    "maintenance",
    "unit System",
    "no quiesce",
    "commit",
])

_wait_for_exit(ctx)
ctx.info("Maintenance unit exited; waiting for final peer recovery and "
         "maintenance acknowledgment to clear.")
current = _wait_for_peer_recovery(ctx, baseline, peer_recovery_timeout)
_check_peer_regression(baseline, current)

ctx.info("BGP peer validation passed; removing temporary maintenance state.")
_cleanup_maintenance(ctx, markers)
ctx.info("Temporary marker aliases and owned maintenance state were removed.")
ctx.info("Saving cleaned startup configuration.")
_run(ctx, ["enable", "copy running-config startup-config"])
ctx.info("Exit Stateful BGP Maintenance Mode completed successfully.")
