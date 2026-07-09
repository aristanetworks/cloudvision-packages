# Copyright (c) 2026 Arista Networks, Inc.
# Use of this source code is governed by the Apache License 2.0
# that can be found in the COPYING file.

import importlib.util
import sys
from pathlib import Path


sys.dont_write_bytecode = True

MODULE_PATH = (
    Path(__file__).resolve().parents[1]
    / "src"
    / "studio-image-preload-action-pack"
    / "studio-image-preload"
    / "script.py"
)


def load_module():
    spec = importlib.util.spec_from_file_location("studio_image_preload", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def sample_repo():
    return [
        {
            "result": {
                "value": {
                    "key": {"name": "EOS-4.34.7M.swi"},
                    "version": "4.34.7M",
                    "fileServerPath": (
                        "software/91f501e8-5baf-4713-bce6-341597d496da/"
                        "EOS-4.34.7M.swi"
                    ),
                    "size": 12345,
                    "sha512": "abc123",
                }
            }
        },
        {
            "result": {
                "value": {
                    "key": {"name": "EOS64-4.30.5M.swi"},
                    "version": "4.30.5M",
                    "fileServerPath": (
                        "/api/v1/files/software/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/"
                        "EOS64-4.30.5M.swi"
                    ),
                    "sizeBytes": 98765,
                }
            }
        },
    ]


def test_url_construction_uses_modern_file_api():
    module = load_module()

    url = module.build_file_api_url(
        "10.255.0.11",
        "software/91f501e8-5baf-4713-bce6-341597d496da/EOS-4.34.7M.swi",
    )

    assert url == (
        "https://10.255.0.11/api/v1/files/software/"
        "91f501e8-5baf-4713-bce6-341597d496da/EOS-4.34.7M.swi"
    )
    assert "/cvpservice/image/getImagebyId/" not in url


def test_old_image_endpoint_is_rejected():
    module = load_module()

    try:
        module.build_file_api_url(
            "10.255.0.11",
            "/cvpservice/image/getImagebyId/EOS-4.34.7M.swi",
        )
    except ValueError as err:
        assert "legacy image endpoint" in str(err)
    else:
        raise AssertionError("legacy endpoint was accepted")


def test_resolve_designed_uses_assigned_artifact_for_device():
    module = load_module()
    designed = {
        "deviceId": "JPE22111081",
        "designedImage": "EOS-4.34.7M.swi",
    }

    artifact = module.resolve_artifact(
        source="designed",
        device_id="JPE22111081",
        repository=sample_repo(),
        designed=designed,
        running={"softwareVersion": "4.30.5M"},
        repository_image="",
    )

    assert artifact.filename == "EOS-4.34.7M.swi"
    assert artifact.file_server_path == (
        "software/91f501e8-5baf-4713-bce6-341597d496da/EOS-4.34.7M.swi"
    )


def test_resolve_designed_filters_assignment_records_by_device():
    module = load_module()
    designed = [
        {
            "deviceIds": ["OTHER"],
            "fileServerPath": (
                "software/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/"
                "EOS64-4.30.5M.swi"
            ),
        },
        {
            "deviceIds": ["JPE22111081"],
            "designedImage": "EOS-4.34.7M.swi",
        },
    ]

    artifact = module.resolve_artifact(
        source="designed",
        device_id="JPE22111081",
        repository=sample_repo(),
        designed=designed,
        running={},
        repository_image="",
    )

    assert artifact.filename == "EOS-4.34.7M.swi"


def test_resolve_running_matches_running_version_from_inventory():
    module = load_module()

    artifact = module.resolve_artifact(
        source="running",
        device_id="JPE22111081",
        repository=sample_repo(),
        designed={},
        running={"softwareVersion": "4.30.5M"},
        repository_image="",
    )

    assert artifact.filename == "EOS64-4.30.5M.swi"
    assert artifact.size == 98765


def test_resolve_repository_uses_human_friendly_image_name():
    module = load_module()

    artifact = module.resolve_artifact(
        source="repository",
        device_id="JPE22111081",
        repository=sample_repo(),
        designed={},
        running={},
        repository_image="4.34.7M",
    )

    assert artifact.filename == "EOS-4.34.7M.swi"


def test_render_preload_command_uses_mgmt_namespace_source_ip_and_swadapt():
    module = load_module()
    artifact = module.Artifact(
        name="EOS-4.34.7M.swi",
        filename="EOS-4.34.7M.swi",
        file_server_path="software/91f501e8-5baf-4713-bce6-341597d496da/EOS-4.34.7M.swi",
        size=12345,
    )

    command = module.render_preload_command(
        url=module.build_file_api_url("10.255.0.11", artifact.file_server_path),
        destination="/mnt/flash/EOS-4.34.7M.swi",
        vrf="MGMT",
        source_ip="10.255.11.112",
        token="secret-token",
        redacted=True,
    )

    assert "sudo ip netns exec ns-MGMT curl" in command
    assert "--interface 10.255.11.112" in command
    assert '--cookie "access_token=<redacted>"' in command
    assert "secret-token" not in command
    assert "| /export/swi/swadapt /mnt/flash/EOS-4.34.7M.swi" in command
    assert "/cvpservice/image/getImagebyId/" not in command


def test_render_preload_command_matches_set_image_guardrails():
    module = load_module()

    command = module.render_preload_command(
        url="https://10.255.0.11/api/v1/files/software/id/EOS-4.34.7M.swi",
        destination="/mnt/flash/EOS-4.34.7M.swi",
        vrf="MGMT",
        source_ip="10.255.11.112",
        token="secret-token",
    )

    assert command.startswith("bash timeout 3597 ")
    assert "--speed-time 120" in command
    assert "--speed-limit 102400" in command
    assert "--fail" in command
    assert "--insecure" in command


def test_command_errors_redact_access_token_cookie_values():
    module = load_module()

    errors = module.command_errors([
        {"error": 'curl --cookie "access_token=secret-token" failed'},
    ])

    assert errors == ['curl --cookie "access_token=<redacted>" failed']


def test_idempotency_skips_matching_file_and_rewrites_partial_file():
    module = load_module()
    artifact = module.Artifact(
        name="EOS-4.34.7M.swi",
        filename="EOS-4.34.7M.swi",
        file_server_path="software/id/EOS-4.34.7M.swi",
        size=12345,
    )

    assert (
        module.plan_download(existing_size=12345, artifact=artifact, force=False).action
        == "skip"
    )
    assert (
        module.plan_download(existing_size=12000, artifact=artifact, force=False).action
        == "rewrite"
    )
    assert (
        module.plan_download(existing_size=12345, artifact=artifact, force=True).action
        == "rewrite"
    )
