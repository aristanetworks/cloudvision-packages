# Copyright (c) 2026 Arista Networks, Inc.
# Use of this source code is governed by the Apache License 2.0
# that can be found in the COPYING file.

import importlib.util
import json
import re
import shlex
from types import SimpleNamespace
import unittest
from pathlib import Path


SCRIPT = (
    Path(__file__).resolve().parents[1]
    / "src"
    / "studio-image-preload-action-pack"
    / "studio-image-preload"
    / "script.py"
)
CONFIG = SCRIPT.with_name("config.yaml")

LOG_ENVELOPE = re.compile(
    r"^Step: (?P<step>[^|\r\n]+) \| "
    r"Status: (?P<status>STARTED|SUCCESS|WARNING|ERROR|SKIPPED) \| "
    r"[^\r\n]+$"
)


def load_script():
    spec = importlib.util.spec_from_file_location("studio_image_preload", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def bash_payload(command):
    parts = shlex.split(command)
    return parts[parts.index("-c") + 1]


class FakeAction:
    def __init__(self, args):
        self.args = args


class FakeConnections:
    apiserverAddr = "api.example"
    serviceAddr = "service.example."


class FakeDevice:
    id = "JPE00000001"
    ip = "192.0.2.99"


class FakeUser:
    token = "secret-token"


class FakeCtx:
    def __init__(self, args, responses):
        self.action = FakeAction(args)
        self.connections = FakeConnections()
        self.device = FakeDevice()
        self.user = FakeUser()
        self.responses = responses
        self.http_paths = []
        self.commands = []
        self.infos = []
        self.transfer_ran = False
        self.transferred_paths = set()
        self.existing_size = None
        self.existing_sizes = {}
        self.checksum_response = "readback-md5  /mnt/flash/EOS-4.34.7M.swi"
        self.verify_response = (
            "Verifying flash:EOS-4.34.7M.swi successful."
        )
        self.verify_error = ""
        self.verify_errors = {}
        self.transfer_exception = None
        self.cleanup_exception = None

    def httpGet(self, path):
        self.http_paths.append(path)
        response = self.responses.get(path)
        if isinstance(response, Exception):
            raise response
        if response is None:
            raise ValueError(f"unexpected path {path}")
        return response

    def runDeviceCmds(self, commands, **kwargs):
        command = commands[-1]
        self.commands.append(command)
        if "stat -c %s" in command:
            match = re.search(r"stat -c %s ([^ ]+)", command)
            destination = match.group(1).strip("'\"") if match else ""
            if destination in self.existing_sizes:
                size = self.existing_sizes[destination]
                return [{"response": "" if size is None else str(size)}]
            if self.existing_size is not None:
                return [{"response": str(self.existing_size)}]
            if destination in self.transferred_paths:
                return [{"response": "4096"}]
            return [{"response": ""}]
        if "md5sum" in command or "sha512sum" in command:
            return [{"response": self.checksum_response}]
        if "rm -f -- " in command:
            if self.cleanup_exception:
                raise self.cleanup_exception
            return [{"response": ""}]
        if command.startswith("verify flash:"):
            errors = self.verify_errors.get(command, [])
            if errors:
                return [{"error": errors.pop(0)}]
            if self.verify_error:
                return [{"error": self.verify_error}]
            return [{"response": self.verify_response}]
        if "curl " in command and ("/export/swi/swadapt" in command or "--output" in command):
            if self.transfer_exception:
                raise self.transfer_exception
            self.transfer_ran = True
            swadapt_match = re.search(r"/export/swi/swadapt ([^' ]+)", command)
            output_match = re.search(r"--output ([^' ]+)", command)
            match = swadapt_match or output_match
            if match:
                self.transferred_paths.add(match.group(1).strip("'\""))
        return [{"response": ""}]

    def info(self, message):
        self.infos.append(message)


class FakeApiCtx(FakeCtx):
    def __init__(self, args, responses, api_clients):
        super().__init__(args, responses)
        self.api_clients = api_clients

    def getApiClient(self, stub_cls):
        return self.api_clients[stub_cls]


class SoftwareRepositoryStub:
    pass


class SoftwareRepositoryConfigStub:
    pass


class SoftwareAssignmentsStub:
    pass


class InventoryProvisionedDeviceStub:
    pass


class InventoryDeviceStub:
    pass


class ImageSummaryStub:
    pass


class StudioInputsStub:
    pass


class StudioInputsConfigStub:
    pass


class TagElementStub:
    pass


class StreamRequest:
    pass


class ElementStreamRequest:
    def __init__(self, filter=None):
        self.filter = filter


class ElementFilter:
    def __init__(self, search=None):
        self.search = search


class ElementSearchFilter:
    def __init__(self, query_element_type=None, query=None):
        self.query_element_type = query_element_type
        self.query = query


class KeyedRequest:
    def __init__(self, key=None):
        self.key = key


class RepositoryKey:
    def __init__(self, name=None):
        self.name = name


class DeviceKey:
    def __init__(self, device_id=None):
        self.device_id = device_id


class SummaryKey:
    def __init__(self, device_id=None):
        self.device_id = device_id


class GetAllClient:
    def __init__(self, records=None, error=None):
        self.records = records or []
        self.error = error
        self.calls = 0

    def GetAll(self, request, timeout=None):
        self.calls += 1
        if self.error:
            raise self.error
        for record in self.records:
            yield record


class GetOneClient:
    def __init__(self, records=None, error=None):
        self.records = records or {}
        self.error = error
        self.calls = 0

    def GetOne(self, request, timeout=None):
        self.calls += 1
        if self.error:
            raise self.error
        key = resource_key_value(request.key)
        if key not in self.records:
            raise ValueError(f"not found: {key}")
        record = self.records[key]
        if isinstance(record, Exception):
            raise record
        return record


class AssignmentsClient(GetOneClient):
    def __init__(self, records=None, all_records=None):
        super().__init__(records)
        self.all_records = all_records or []
        self.get_all_calls = 0

    def GetAll(self, request, timeout=None):
        self.get_all_calls += 1
        yield from self.all_records


class TagElementClient:
    def __init__(self, records_by_query=None, error=None):
        self.records_by_query = records_by_query or {}
        self.error = error
        self.requests = []

    def GetAll(self, request, timeout=None):
        self.requests.append((request, timeout))
        if self.error:
            raise self.error
        query = wrapped_value(request.filter.search.query)
        yield from self.records_by_query.get(query, [])


def wrapped_value(value):
    if isinstance(value, dict):
        return value.get("value")
    return getattr(value, "value", value)


def resource_key_value(key):
    for field in ("name", "device_id"):
        value = getattr(key, field, None)
        if isinstance(value, dict):
            return value.get("value")
        if value is not None:
            return getattr(value, "value", value)
    return None


class StudioImagePreloadTests(unittest.TestCase):
    def setUp(self):
        self.module = load_script()

    def test_swi_classification_is_case_insensitive(self):
        image = self.module.Artifact(
            name="EOS-4.34.6M.SWI",
            filename="EOS-4.34.6M.SWI",
            file_server_path="software/image/EOS-4.34.6M.SWI",
        )

        self.assertTrue(self.module.is_swi_artifact(image))

    def test_eos_verifiable_artifact_classification_is_case_insensitive(self):
        cases = (
            ("EOS-4.34.6M.swi", True),
            ("EOS-4.34.6M.SWI", True),
            ("TerminAttr-1.40.10-1.swix", True),
            ("fabric-health-agent.SWIX", True),
            ("extension.rpm", False),
            ("checksum.txt", False),
        )
        for filename, expected in cases:
            with self.subTest(filename=filename):
                artifact = self.module.Artifact(
                    name=filename,
                    filename=filename,
                    file_server_path=f"software/uuid/{filename}",
                )
                self.assertEqual(
                    self.module.is_eos_verifiable_artifact(artifact),
                    expected,
                )

    def test_uppercase_swi_extension_parses_version_and_matches_version_selector(self):
        artifact = self.module.Artifact(
            name="EOS-4.34.6M.SWI",
            filename="EOS-4.34.6M.SWI",
            file_server_path="software/image/EOS-4.34.6M.SWI",
        )

        self.assertEqual(
            self.module.parse_version_from_filename(artifact.filename),
            "4.34.6M",
        )
        self.assertIs(
            self.module.find_repository_selector(
                [artifact], "4.34.6M", "Repository Image"
            ),
            artifact,
        )

    def resource_ctx(self, args, repository_state=None, repository_config=None,
                     assignments=None, assignment_records=None, image_summary=None,
                     inventory_device=None, provisioned_device=None, studio_inputs=None,
                     studio_inputs_config=None, assignments_available=True,
                     tag_query_results=None, tag_query_error=None,
                     tag_api_available=True, tag_stub_available=True):
        software_service_attrs = {
            "RepositoryServiceStub": SoftwareRepositoryStub,
            "RepositoryConfigServiceStub": SoftwareRepositoryConfigStub,
            "RepositoryStreamRequest": StreamRequest,
            "RepositoryConfigStreamRequest": StreamRequest,
        }
        if assignments_available:
            software_service_attrs.update({
                "AssignmentsServiceStub": SoftwareAssignmentsStub,
                "AssignmentsRequest": KeyedRequest,
            })
            if assignment_records is not None:
                software_service_attrs["AssignmentsStreamRequest"] = StreamRequest
        software_services = SimpleNamespace(**software_service_attrs)
        software_models = SimpleNamespace(RepositoryKey=RepositoryKey)
        inventory_services = SimpleNamespace(
            ProvisionedDeviceServiceStub=InventoryProvisionedDeviceStub,
            DeviceServiceStub=InventoryDeviceStub,
            ProvisionedDeviceRequest=KeyedRequest,
            DeviceRequest=KeyedRequest,
        )
        inventory_models = SimpleNamespace(DeviceKey=DeviceKey)
        imagestatus_services = SimpleNamespace(
            SummaryServiceStub=ImageSummaryStub,
            SummaryRequest=KeyedRequest,
        )
        imagestatus_models = SimpleNamespace(SummaryKey=SummaryKey)
        studio_services = SimpleNamespace(
            InputsServiceStub=StudioInputsStub,
            InputsConfigServiceStub=StudioInputsConfigStub,
            InputsStreamRequest=StreamRequest,
            InputsConfigStreamRequest=StreamRequest,
        )
        tag_service_attrs = {"ElementStreamRequest": ElementStreamRequest}
        if tag_stub_available:
            tag_service_attrs["ElementServiceStub"] = TagElementStub
        tag_services = SimpleNamespace(**tag_service_attrs)
        tag_models = SimpleNamespace(
            ElementFilter=ElementFilter,
            ElementSearchFilter=ElementSearchFilter,
        )

        def fake_import_module(name):
            modules = {
                "arista.softwaremanagement.v1.services": software_services,
                "arista.softwaremanagement.v1": software_models,
                "arista.inventory.v1.services": inventory_services,
                "arista.inventory.v1": inventory_models,
                "arista.imagestatus.v1.services": imagestatus_services,
                "arista.imagestatus.v1": imagestatus_models,
                "arista.studio.v1.services": studio_services,
            }
            if tag_api_available:
                modules.update({
                    "arista.tag.v2.services": tag_services,
                    "arista.tag.v2": tag_models,
                })
            if name not in modules:
                raise ImportError(name)
            return modules[name]

        self.module.import_module = fake_import_module
        assignments_client = AssignmentsClient(assignments, assignment_records)
        tag_client = TagElementClient(tag_query_results, tag_query_error)
        studio_inputs_client = GetAllClient(
            studio_inputs, ValueError("not found")
            if studio_inputs is None else None
        )
        studio_inputs_config_client = GetAllClient(
            studio_inputs_config, ValueError("not found")
            if studio_inputs_config is None else None
        )
        image_summary_client = GetOneClient(image_summary)
        ctx = FakeApiCtx(
            args,
            {},
            {
                SoftwareRepositoryStub: GetAllClient(
                    repository_state, ValueError("not found")
                    if repository_state is None else None
                ),
                SoftwareRepositoryConfigStub: GetAllClient(repository_config),
                SoftwareAssignmentsStub: assignments_client,
                ImageSummaryStub: image_summary_client,
                InventoryDeviceStub: GetOneClient(inventory_device),
                InventoryProvisionedDeviceStub: GetOneClient(provisioned_device),
                StudioInputsStub: studio_inputs_client,
                StudioInputsConfigStub: studio_inputs_config_client,
                TagElementStub: tag_client,
            },
        )
        ctx.assignments_client = assignments_client
        ctx.tag_client = tag_client
        ctx.studio_inputs_client = studio_inputs_client
        ctx.studio_inputs_config_client = studio_inputs_config_client
        ctx.image_summary_client = image_summary_client
        return ctx

    def assert_structured_logs(self, ctx):
        self.assertTrue(ctx.infos)
        for message in ctx.infos:
            self.assertRegex(message, LOG_ENVELOPE)

    def log_events(self, ctx):
        events = []
        for message in ctx.infos:
            match = LOG_ENVELOPE.fullmatch(message)
            self.assertIsNotNone(match, message)
            events.append((match.group("step"), match.group("status")))
        return events

    def repository_config_records(self):
        return [
            {
                "result": {
                    "value": {
                        "key": {"name": "EOS-4.34.6M.swi"},
                        "uri": "/software/repository-image/EOS-4.34.6M.swi",
                    }
                }
            },
            {
                "result": {
                    "value": {
                        "key": {"name": "EOS-4.35.4M.swi"},
                        "uri": "/software/repository-secondary-image/EOS-4.35.4M.swi",
                    }
                }
            },
            {
                "result": {
                    "value": {
                        "key": {"name": "EOS-4.36.0F.swi"},
                        "uri": "/support/download/EOS-USA/Active Releases/EOS-4.36.0F.swi",
                    }
                }
            },
        ]

    def repository_state_records(self):
        return [
            {
                "result": {
                    "value": {
                        "key": {"name": "EOS-4.36.0F.swi"},
                        "softwareMetadata": {
                            "fileServerPath": "software/state/EOS-4.36.0F.swi",
                            "size": 4096,
                            "digest": "sha512-value",
                            "swiMetadata": {"version": "4.36.0F"},
                        },
                    }
                }
            }
        ]

    def extension_repository_config_records(self):
        return [
            {
                "result": {
                    "value": {
                        "key": {"name": "TerminAttr-1.40.10-1.swix"},
                        "uri": "/software/repository-agent/TerminAttr-1.40.10-1.swix",
                    }
                }
            },
            {
                "result": {
                    "value": {
                        "key": {"name": "switchapp-1.15.1-1.10.swix"},
                        "uri": "/software/repository-extension/switchapp-1.15.1-1.10.swix",
                    }
                }
            },
        ]

    def repository_artifact_records(self, names):
        return [
            {
                "result": {
                    "value": {
                        "key": {"name": name},
                        "uri": f"/software/{index}/{name}",
                    }
                }
            }
            for index, name in enumerate(names)
        ]

    def repository_artifacts_context(self, args, names):
        return self.resource_ctx(
            args,
            repository_config=self.repository_artifact_records(names),
            provisioned_device={"JPE00000001": self.provisioned_device()},
        )

    def test_parse_csv_list_strips_empties_deduplicates_casefolded_and_preserves_order(self):
        self.assertEqual(
            self.module.parse_csv_list(
                " first.swix, ,SECOND.rpm,first.SWIX, second.RPM,third.swix, "
            ),
            ["first.swix", "SECOND.rpm", "third.swix"],
        )

    def test_repository_resolves_image_agent_and_extensions_in_order(self):
        names = [
            "EOS-4.34.6M.swi",
            "TerminAttr-1.40.10-1.swix",
            "switchapp-1.15.1.swix",
            "otheragent-2.0.swix",
        ]
        ctx = self.repository_artifacts_context(
            {}, names
        )

        selected = self.module.resolve_runtime_artifacts(
            ctx,
            "repository",
            "JPE00000001",
            "EOS-4.34.6M.swi",
            "TerminAttr-1.40.10-1.swix",
            "switchapp-1.15.1.swix, otheragent-2.0.swix",
        )

        self.assertEqual([artifact.filename for artifact in selected], names)

    def test_repository_image_agent_and_extensions_preload_in_order_by_command_type(self):
        names = [
            "EOS-4.34.6M.swi",
            "TerminAttr-1.40.10-1.swix",
            "switchapp-1.15.1.swix",
            "otheragent-2.0.swix",
        ]
        ctx = self.repository_artifacts_context(
            {
                "DeviceID": "JPE00000001",
                "Source": "repository",
                "Repository Image": names[0],
                "Repository Streaming Agent": names[1],
                "Repository Extensions": f"{names[2]}, {names[3]}",
                "VRF": "MGMT",
                "Force": "False",
            },
            names,
        )

        self.module.run(ctx)

        self.assertFalse(any("Parameter check" in message for message in ctx.infos))
        transfers = [
            command for command in ctx.commands
            if "curl " in command and ("swadapt" in command or "--output" in command)
        ]
        self.assertEqual(len(transfers), 4)
        self.assertIn("/export/swi/swadapt", transfers[0])
        self.assertNotIn("/export/swi/swadapt", "\n".join(transfers[1:]))
        for name, command in zip(names, transfers):
            self.assertIn(name, command)

    def test_repository_empty_or_auto_selects_embedded_agent_and_no_extensions(self):
        names = [
            "EOS-4.34.6M.swi",
            "TerminAttr-1.40.10-1.swix",
            "switchapp-1.15.1.swix",
        ]
        cases = (
            ("", "", [names[0]]),
            ("auto", "auto", [names[0]]),
            ("", names[2], [names[0], names[2]]),
            ("auto", names[2], [names[0], names[2]]),
            (names[1], "", [names[0], names[1]]),
            (names[1], "auto", [names[0], names[1]]),
        )
        for agent, extensions, expected in cases:
            with self.subTest(agent=agent, extensions=extensions):
                ctx = self.repository_artifacts_context({}, names)
                selected = self.module.resolve_runtime_artifacts(
                    ctx,
                    "repository",
                    "JPE00000001",
                    names[0],
                    agent,
                    extensions,
                )
                self.assertEqual(
                    [artifact.filename for artifact in selected],
                    expected,
                )

    def test_repository_auto_image_is_rejected_for_direct_runtime_resolution(self):
        ctx = self.repository_artifacts_context({}, ["EOS-4.34.6M.swi"])

        with self.assertRaisesRegex(
            ValueError,
            "Repository source requires a repository image name or version",
        ):
            self.module.resolve_runtime_artifacts(
                ctx,
                "repository",
                "JPE00000001",
                "auto",
            )

    def test_repository_resolver_old_callers_remain_compatible(self):
        name = "EOS-4.34.6M.swi"
        ctx = self.repository_artifacts_context({}, [name])

        selected = self.module.resolve_runtime_artifacts(
            ctx, "repository", "JPE00000001", name
        )

        self.assertEqual([artifact.filename for artifact in selected], [name])

    def test_repository_selector_errors_name_field_token_and_match_count(self):
        names = [
            "EOS-4.34.6M.swi",
            "TerminAttr-1.40.10-1.swix",
            "TerminAttr-1.40.10-2.swix",
            "switchapp-1.15.1.swix",
            "other-switchapp-2.0.swix",
        ]
        cases = (
            ("Repository Image", "missing-image.swi", 0),
            ("Repository Image", "TerminAttr", 2),
            ("Repository Streaming Agent", "missing-agent.swix", 0),
            ("Repository Streaming Agent", "TerminAttr", 2),
            ("Repository Extensions", "missing-extension.swix", 0),
            ("Repository Extensions", "switchapp", 2),
        )
        for field, token, count in cases:
            with self.subTest(field=field, token=token):
                ctx = self.repository_artifacts_context({}, names)
                kwargs = {
                    "repository_image": token
                    if field == "Repository Image" else names[0],
                    "repository_agent": token
                    if field == "Repository Streaming Agent" else "",
                    "repository_extensions": token
                    if field == "Repository Extensions" else "",
                }
                with self.assertRaisesRegex(
                    ValueError,
                    rf"{field}.*'{token}'.*matched {count} artifacts",
                ) as raised:
                    self.module.resolve_runtime_artifacts(
                        ctx,
                        "repository",
                        "JPE00000001",
                        **kwargs,
                    )
                if count > 1:
                    self.assertIn("be more specific", str(raised.exception))

    def test_non_repository_agent_and_extensions_are_ignored_with_one_warning(self):
        ctx = self.resource_ctx(
            {
                "DeviceID": "JPE00000001",
                "Source": "designed",
                "Repository Image": "image.swi",
                "Repository Streaming Agent": "agent.swix",
                "Repository Extensions": "extension.swix",
                "VRF": "MGMT",
                "Force": "False",
            },
            repository_config=self.designed_repository_config_records(),
            assignment_records=[
                self.assignment_record("EOS-4.34.6M.swi", "JPE00000001")
            ],
            studio_inputs=[self.studio_software_inputs_record(
                agent="", extensions=(), path={}
            )],
        )

        self.module.run(ctx)

        warnings = [
            message for message in ctx.infos
            if message.startswith("Step: Parameter check | Status: WARNING | ")
        ]
        self.assertEqual(len(warnings), 1)
        self.assertIn("these inputs are ignored", warnings[0])
        self.assertIn(
            "Repository Image, Repository Streaming Agent, and Repository Extensions provided",
            warnings[0],
        )
        self.assertIn("EOS-4.34.6M.swi", "\n".join(ctx.commands))

    def test_non_repository_warning_names_only_each_provided_field(self):
        fields = (
            "Repository Streaming Agent",
            "Repository Extensions",
            "Repository Image",
        )
        for field in fields:
            with self.subTest(field=field):
                ctx = self.resource_ctx(
                    {
                        "DeviceID": "JPE00000001",
                        "Source": "designed",
                        field: "provided-value",
                        "VRF": "MGMT",
                        "Force": "False",
                    },
                    repository_config=self.designed_repository_config_records(),
                    assignment_records=[
                        self.assignment_record("EOS-4.34.6M.swi", "JPE00000001")
                    ],
                    studio_inputs=[self.studio_software_inputs_record(
                        agent="", extensions=(), path={}
                    )],
                )

                self.module.run(ctx)

                warnings = [
                    message for message in ctx.infos
                    if message.startswith("Step: Parameter check | Status: WARNING | ")
                ]
                self.assertEqual(len(warnings), 1)
                self.assertIn(field + " provided", warnings[0])
                self.assertIn("this input is ignored", warnings[0])
                self.assertNotIn("these inputs are ignored", warnings[0])
                for other_field in fields:
                    if other_field != field:
                        self.assertNotIn(other_field, warnings[0])
                self.assertIn("EOS-4.34.6M.swi", "\n".join(ctx.commands))

    def test_running_source_ignores_repository_agent_and_extensions_with_one_warning(self):
        ctx = self.resource_ctx(
            {
                "DeviceID": "JPE00000001",
                "Source": "running",
                "Repository Streaming Agent": "agent.swix",
                "Repository Extensions": "extension.swix",
                "VRF": "MGMT",
                "Force": "False",
            },
            repository_config=[self.repository_config_records()[0]],
            provisioned_device={"JPE00000001": self.provisioned_device()},
            inventory_device={"JPE00000001": self.inventory_device()},
        )

        self.module.run(ctx)

        warnings = [
            message for message in ctx.infos
            if message.startswith("Step: Parameter check | Status: WARNING | ")
        ]
        self.assertEqual(len(warnings), 1)
        self.assertIn(
            "Repository Streaming Agent and Repository Extensions provided",
            warnings[0],
        )
        self.assertNotIn("Repository Image", warnings[0])
        self.assertIn("EOS-4.34.6M.swi", "\n".join(ctx.commands))

    def test_explicit_source_uses_repository_agent_and_extensions_without_warning(self):
        names = [
            "EOS-4.34.6M.swi",
            "TerminAttr-1.40.10-1.swix",
            "switchapp-1.15.1.swix",
        ]
        ctx = self.repository_artifacts_context(
            {
                "DeviceID": "JPE00000001",
                "Source": "explicit",
                "Repository Image": names[0],
                "repository_streaming_agent": names[1],
                "repository_extensions": names[2],
                "VRF": "MGMT",
                "Force": "False",
            },
            names,
        )

        self.module.run(ctx)

        self.assertFalse(any("Parameter check" in message for message in ctx.infos))
        self.assertEqual(
            sum("curl " in command and ("swadapt" in command or "--output" in command)
                for command in ctx.commands),
            3,
        )

    def test_destination_collision_fails_before_any_device_command(self):
        names = ["EOS-4.34.6M.swi", "same-name.swix"]
        ctx = self.repository_artifacts_context(
            {
                "DeviceID": "JPE00000001",
                "Source": "repository",
                "Repository Image": names[0],
                "Repository Extensions": names[1],
                "Destination": "/mnt/flash/same-name.swix",
                "Force": "False",
            },
            names,
        )

        with self.assertRaisesRegex(
            ValueError,
            "collision.*EOS-4.34.6M.swi.*same-name.swix.*same-name.swix",
        ) as raised:
            self.module.run(ctx)

        message = str(raised.exception)
        self.assertIn("/mnt/flash/same-name.swix", message)
        self.assertNotIn("software/0/EOS-4.34.6M.swi", message)
        self.assertNotIn("software/1/same-name.swix", message)
        self.assertEqual(ctx.commands, [])

    def test_repository_config_contains_approved_agent_and_extension_parameters(self):
        config = CONFIG.read_text()
        self.assertIn(
            """- name: Repository Image
    description: >-
      Software Management artifact name or version for repository mode
      (e.g. EOS-4.34.7M.swi or 4.34.7M). Leave auto otherwise; only used when
      Source is repository.
    required: false
    hidden: false
    default: auto""",
            config,
        )
        self.assertIn(
            """- name: Repository Streaming Agent
    description: >-
      TerminAttr streaming agent artifact name or version for repository mode
      (e.g. TerminAttr-1.40.10-1.swix). Leave auto to use the EOS embedded
      agent. Only used when Source is repository; ignored otherwise.
    required: false
    hidden: false
    default: auto""",
            config,
        )
        self.assertIn(
            """- name: Repository Extensions
    description: >-
      Extension artifact names or versions for repository mode, comma-separated
      (e.g. switchapp-1.15.1-1.10.swix, otheragent-2.0.swix). Leave auto when no
      extensions are needed. Only used when Source is repository; ignored
      otherwise.
    required: false
    hidden: false
    default: auto""",
            config,
        )

    def test_readme_examples_follow_action_config_parameter_order(self):
        readme = (SCRIPT.parents[1] / "README.md").read_text()
        blocks = [
            block for block in re.findall(r"```text\n(.*?)\n```", readme, re.DOTALL)
            if "Source:" in block and "Force:" in block
        ]
        expected = [
            "Source",
            "Repository Image",
            "Repository Streaming Agent",
            "Repository Extensions",
            "Authority",
            "VRF",
            "Source IP",
            "Destination",
            "Force",
        ]
        self.assertEqual(len(blocks), 2)
        for block in blocks:
            self.assertEqual(
                [line.split(":", 1)[0] for line in block.splitlines()],
                expected,
            )

    def designed_repository_config_records(self):
        return (
            [self.repository_config_records()[0]]
            + self.extension_repository_config_records()
        )

    def studio_software_inputs_record(self, image="EOS-4.34.6M.swi",
                                      agent="TerminAttr-1.40.10-1.swix",
                                      extensions=("switchapp-1.15.1-1.10.swix",),
                                      query="device:JPE00000001",
                                      workspace_id="", path=None,
                                      studio_id="studio-software-management",
                                      include_image=True, include_agent=True,
                                      include_extensions=True):
        software_group = {}
        if include_image:
            software_group["imageName"] = image
        if include_agent:
            software_group["streamingAgentName"] = agent
        if include_extensions:
            software_group["extensionsCollection"] = [
                {"extensionName": extension}
                for extension in extensions
            ]
        return self.studio_software_resolvers_record([
            {
                "inputs": {"softwareGroup": software_group},
                "tags": {"query": query},
            },
        ], workspace_id=workspace_id, path=path, studio_id=studio_id)

    def studio_software_resolvers_record(self, resolvers, workspace_id="",
                                         path=None,
                                         studio_id="studio-software-management"):
        key = {
            "studioId": studio_id,
            "workspaceId": workspace_id,
        }
        if path is not None:
            key["path"] = path
        return {
            "value": {
                "key": key,
                "inputs": json.dumps({
                    "softwareResolver": resolvers,
                }),
            },
        }

    def studio_inputs_fragments(self, payload, cuts):
        boundaries = (0,) + tuple(cuts) + (len(payload),)
        fragments = [
            payload[start:end]
            for start, end in zip(boundaries, boundaries[1:])
        ]
        records = []
        for index, fragment in enumerate(fragments):
            if index % 2:
                key = {
                    "studio_id": "studio-software-management",
                    "workspace_id": "",
                    "path": {"values": []},
                }
            else:
                key = {
                    "studioId": "studio-software-management",
                    "workspaceId": "",
                    "path": {},
                }
            records.append({"value": {"key": key, "inputs": fragment}})
        return records

    def tag_element(self, device_id, key_field="primary_id"):
        return {"value": {"key": {key_field: device_id}}}

    def designed_resolution_logs(self, ctx):
        return [
            message for message in ctx.infos
            if message.startswith("Step: Designed resolution | ")
        ]

    def assignment_record(self, name, *device_ids, key_field="name"):
        return {
            "value": {
                "key": {key_field: {"value": name}},
                "devices": {
                    "values": [
                        {"deviceId": device_id}
                        for device_id in device_ids
                    ],
                },
            },
        }

    def provisioned_device(self):
        return {
            "value": {
                "key": {"deviceId": "JPE00000001"},
                "ipAddress": {"value": "192.0.2.221"},
            }
        }

    def inventory_device(self):
        return {
            "value": {
                "key": {"deviceId": "JPE00000001"},
                "softwareVersion": "4.34.6M",
            }
        }

    def test_repository_state_metadata_supplies_file_server_path_for_cloud_uri(self):
        ctx = self.resource_ctx(
            {},
            repository_state=self.repository_state_records(),
            repository_config=self.repository_config_records(),
        )

        artifacts = self.module.artifacts_from_repository(self.module.load_repository(ctx))

        artifact = self.module.find_artifact(artifacts, "EOS-4.36.0F.swi")
        self.assertEqual(artifact.file_server_path, "software/state/EOS-4.36.0F.swi")
        self.assertEqual(artifact.size, 4096)
        self.assertEqual(ctx.http_paths, [])

    def test_repository_uses_resource_api_client_for_streaming_get_all(self):
        module = self.module

        class RepositoryStub:
            pass

        class RepositoryConfigStub:
            pass

        class RepositoryStreamRequest:
            pass

        class RepositoryConfigStreamRequest:
            pass

        class MissingRepositoryState:
            def GetAll(self, request, timeout=None):
                raise ValueError("not found")

        class RepositoryConfigState:
            def GetAll(self, request, timeout=None):
                yield SimpleNamespace(
                    value={
                        "key": {"name": "EOS-4.34.6M.swi"},
                        "uri": "/software/repository-image/EOS-4.34.6M.swi",
                    }
                )

        fake_services = SimpleNamespace(
            RepositoryServiceStub=RepositoryStub,
            RepositoryConfigServiceStub=RepositoryConfigStub,
            RepositoryStreamRequest=RepositoryStreamRequest,
            RepositoryConfigStreamRequest=RepositoryConfigStreamRequest,
        )
        module.import_module = lambda name: fake_services
        ctx = FakeApiCtx(
            {},
            {},
            {
                RepositoryStub: MissingRepositoryState(),
                RepositoryConfigStub: RepositoryConfigState(),
            },
        )

        artifacts = module.artifacts_from_repository(module.load_repository(ctx))

        self.assertEqual(artifacts[0].file_server_path, "software/repository-image/EOS-4.34.6M.swi")
        self.assertEqual(ctx.http_paths, [])

    def test_repository_does_not_fall_back_to_action_http_get(self):
        module = self.module
        module.import_module = lambda name: (_ for _ in ()).throw(ImportError(name))
        ctx = FakeCtx(
            {},
            {
                "/api/resources/softwaremanagement/v1/RepositoryConfig/all": (
                    self.repository_config_records()
                )
            },
        )

        with self.assertRaises(Exception):
            module.load_repository(ctx)

        self.assertEqual(ctx.http_paths, [])

    def test_source_ip_uses_resource_api_client_for_provisioned_device(self):
        module = self.module

        class ProvisionedDeviceStub:
            pass

        class ProvisionedDeviceRequest:
            def __init__(self, key=None):
                self.key = key

        class DeviceKey:
            def __init__(self, device_id=None):
                self.device_id = device_id

        class ProvisionedDeviceState:
            def GetOne(self, request, timeout=None):
                self.request = request
                return SimpleNamespace(
                    value={
                        "key": {"deviceId": "JPE00000001"},
                        "ipAddress": {"value": "192.0.2.221"},
                    }
                )

        fake_services = SimpleNamespace(
            ProvisionedDeviceServiceStub=ProvisionedDeviceStub,
            ProvisionedDeviceRequest=ProvisionedDeviceRequest,
        )
        fake_models = SimpleNamespace(DeviceKey=DeviceKey)

        def fake_import_module(name):
            if name.endswith(".services"):
                return fake_services
            return fake_models

        module.import_module = fake_import_module
        client = ProvisionedDeviceState()
        ctx = FakeApiCtx({}, {}, {ProvisionedDeviceStub: client})

        source_ip = module.get_source_ip(ctx, {}, "JPE00000001")

        self.assertEqual(source_ip, "192.0.2.221")
        self.assertEqual(client.request.key.device_id, {"value": "JPE00000001"})
        self.assertEqual(ctx.http_paths, [])

    def test_render_preload_command_uses_pipefail_and_bounds_pipeline(self):
        command = self.module.render_preload_command(
            "https://api.example/api/v1/files/software/id/EOS-4.34.7M.swi",
            "/mnt/flash/EOS-4.34.7M.swi",
            "MGMT",
            "192.0.2.112",
            'token"$`value',
        )

        self.assertIn("timeout 3597 bash -o pipefail -c", command)
        payload = bash_payload(command)
        self.assertIn("sudo ip netns exec ns-MGMT curl", payload)
        self.assertIn("| /export/swi/swadapt", payload)
        self.assertIn("--cookie 'access_token=token\"$`value'", payload)
        self.assertNotIn('"access_token=token"$`value"', command)

    def test_render_preload_command_omits_namespace_for_default_vrf(self):
        command = self.module.render_preload_command(
            "https://api.example/api/v1/files/software/id/EOS-4.34.7M.swi",
            "/mnt/flash/EOS-4.34.7M.swi",
            "default",
            "192.0.2.112",
            "token",
        )

        self.assertNotIn("ip netns exec ns-default", command)
        self.assertTrue(bash_payload(command).startswith("curl "))

    def test_render_verify_command_shell_quotes_flash_path(self):
        command = self.module.render_verify_command(
            "/mnt/flash/test images/EOS-4.28.13.1M.swi"
        )

        self.assertEqual(
            command,
            "verify 'flash:test images/EOS-4.28.13.1M.swi'",
        )

    def test_sanitize_log_text_redacts_token_and_normalizes_whitespace(self):
        text = "  result\taccess_token=SECRET\nnext\x00line\r\n  "

        sanitized = self.module.sanitize_log_text(text)

        self.assertEqual(
            sanitized,
            "result access_token=<redacted> next line",
        )

    def test_sanitize_log_text_truncation_is_visible_and_bounded(self):
        sanitized = self.module.sanitize_log_text("verification " * 20, limit=60)

        self.assertLessEqual(len(sanitized), 60)
        self.assertTrue(sanitized.endswith("[truncated]"))

    def test_step_log_status_vocabulary_is_explicit_and_rejects_unknown_status(self):
        self.assertEqual(
            self.module.LOG_STATUSES,
            frozenset({"STARTED", "SUCCESS", "WARNING", "ERROR", "SKIPPED"}),
        )
        ctx = FakeCtx({}, {})

        with self.assertRaisesRegex(ValueError, "unknown log status"):
            self.module.log_step(ctx, "Test operation", "DONE", "Detail: complete.")

        self.assertEqual(ctx.infos, [])

    def test_normalize_file_server_path_requires_uuid_and_filename(self):
        with self.assertRaises(ValueError):
            self.module.normalize_file_server_path("software")
        with self.assertRaises(ValueError):
            self.module.normalize_file_server_path("software/uuid")

        self.assertEqual(
            self.module.normalize_file_server_path("software/uuid/EOS-4.34.7M.swi"),
            "software/uuid/EOS-4.34.7M.swi",
        )

    def test_auto_authority_strips_api_server_port_for_file_api_url(self):
        ctx = FakeCtx({}, {})
        ctx.connections = SimpleNamespace(
            apiserverAddr="192.0.2.12:9900",
            serviceAddr="service.example.",
        )

        authority = self.module.get_authority(ctx, {})
        url = self.module.build_file_api_url(
            authority,
            "software/uuid/EOS-4.34.7M.swi",
        )

        self.assertEqual(
            url,
            "https://192.0.2.12/api/v1/files/software/uuid/EOS-4.34.7M.swi",
        )

    def test_explicit_authority_preserves_operator_port(self):
        authority = self.module.get_authority(
            FakeCtx({"Authority": "api.example:8443"}, {}),
            {"Authority": "api.example:8443"},
        )

        self.assertEqual(authority, "api.example:8443")

    def test_plan_download_skips_when_existing_target_verifies(self):
        plan = self.module.plan_download(5120, True, False)

        self.assertEqual(plan.action, "skip")
        self.assertEqual(plan.reason, "target file already verifies")

    def test_plan_download_rewrites_when_existing_target_fails_verification(self):
        plan = self.module.plan_download(5120, False, False)

        self.assertEqual(plan.action, "rewrite")
        self.assertEqual(plan.reason, "target file exists but verification failed")

    def test_verify_download_compares_sha512_for_rpm_when_available(self):
        artifact = self.module.Artifact(
            name="fabric-health-agent-1.0.rpm",
            filename="fabric-health-agent-1.0.rpm",
            file_server_path="software/uuid/fabric-health-agent-1.0.rpm",
            sha512="abc123",
        )
        ctx = FakeCtx({}, {})
        ctx.existing_size = 4096
        ctx.checksum_response = "ABC123  /mnt/flash/fabric-health-agent-1.0.rpm"

        self.module.verify_download(
            ctx,
            artifact,
            "/mnt/flash/fabric-health-agent-1.0.rpm",
        )

        self.assertIn("sha512sum", "\n".join(ctx.commands))
        self.assertEqual(
            self.log_events(ctx),
            [
                ("Checksum verification", "STARTED"),
                ("Checksum verification", "SUCCESS"),
            ],
        )
        self.assertIn("Algorithm: sha512", ctx.infos[0])
        self.assertIn("Artifact: fabric-health-agent-1.0.rpm", ctx.infos[0])
        self.assertIn(
            "Destination: /mnt/flash/fabric-health-agent-1.0.rpm",
            ctx.infos[0],
        )

    def test_rpm_checksum_mismatch_logs_error_without_success(self):
        artifact = self.module.Artifact(
            name="fabric-health-agent-1.0.rpm",
            filename="fabric-health-agent-1.0.rpm",
            file_server_path="software/uuid/fabric-health-agent-1.0.rpm",
            sha512="expected",
        )
        ctx = FakeCtx({}, {})
        ctx.existing_size = 4096
        ctx.checksum_response = "actual  /mnt/flash/fabric-health-agent-1.0.rpm"

        with self.assertRaisesRegex(ValueError, "checksum mismatch"):
            self.module.verify_download(
                ctx,
                artifact,
                "/mnt/flash/fabric-health-agent-1.0.rpm",
            )

        self.assertEqual(
            self.log_events(ctx),
            [
                ("Checksum verification", "STARTED"),
                ("Checksum verification", "ERROR"),
            ],
        )
        self.assertIn("Algorithm: sha512", ctx.infos[-1])
        self.assertNotIn("Status: SUCCESS", "\n".join(ctx.infos))

    def test_terminattr_swix_uses_eos_verify_despite_sha512_metadata(self):
        artifact = self.module.Artifact(
            name="TerminAttr-1.40.10-1.swix",
            filename="TerminAttr-1.40.10-1.swix",
            file_server_path="software/uuid/TerminAttr-1.40.10-1.swix",
            sha512="repository-digest",
        )
        ctx = FakeCtx({}, {})
        ctx.existing_size = 4096
        ctx.verify_response = (
            "Verifying flash:TerminAttr-1.40.10-1.swix\n"
            "package is valid."
        )

        self.module.verify_download(
            ctx,
            artifact,
            "/mnt/flash/TerminAttr-1.40.10-1.swix",
        )

        commands = "\n".join(ctx.commands)
        self.assertIn("verify flash:TerminAttr-1.40.10-1.swix", commands)
        self.assertNotIn("sha512sum", commands)
        self.assertNotIn("md5sum", commands)
        self.assertEqual(
            ctx.infos,
            [
                "Step: EOS package verification | Status: STARTED | "
                "Artifact: TerminAttr-1.40.10-1.swix; "
                "Destination: /mnt/flash/TerminAttr-1.40.10-1.swix; "
                "Device verify command: verify flash:TerminAttr-1.40.10-1.swix",
                "Step: EOS package verification | Status: SUCCESS | "
                "Artifact: TerminAttr-1.40.10-1.swix; "
                "Destination: /mnt/flash/TerminAttr-1.40.10-1.swix; "
                "Device response: Verifying flash:TerminAttr-1.40.10-1.swix "
                "package is valid.",
            ],
        )

    def test_extension_swix_eos_verify_accepts_empty_success_response(self):
        artifact = self.module.Artifact(
            name="Fabric Health Agent",
            filename="fabric-health-agent-1.0.SWIX",
            file_server_path="software/uuid/fabric-health-agent-1.0.SWIX",
            sha512="repository-digest",
        )
        ctx = FakeCtx({}, {})
        ctx.existing_size = 4096
        ctx.verify_response = ""

        self.module.verify_download(
            ctx,
            artifact,
            "/mnt/flash/fabric-health-agent-1.0.SWIX",
        )

        commands = "\n".join(ctx.commands)
        self.assertIn("verify flash:fabric-health-agent-1.0.SWIX", commands)
        self.assertNotIn("sha512sum", commands)
        self.assertNotIn("md5sum", commands)
        self.assertEqual(
            ctx.infos,
            [
                "Step: EOS package verification | Status: STARTED | "
                "Artifact: fabric-health-agent-1.0.SWIX; "
                "Destination: /mnt/flash/fabric-health-agent-1.0.SWIX; "
                "Device verify command: verify flash:fabric-health-agent-1.0.SWIX",
                "Step: EOS package verification | Status: SUCCESS | "
                "Artifact: fabric-health-agent-1.0.SWIX; "
                "Destination: /mnt/flash/fabric-health-agent-1.0.SWIX; "
                "Device response: "
                "(none; absence of Command API error confirms success).",
            ],
        )

    def test_swix_verify_download_logs_error_and_reraises_command_error(self):
        artifact = self.module.Artifact(
            name="switchapp-1.15.1.swix",
            filename="switchapp-1.15.1.swix",
            file_server_path="software/uuid/switchapp-1.15.1.swix",
            md5="repository-digest",
        )
        ctx = FakeCtx({}, {})
        ctx.existing_size = 4096
        ctx.verify_error = "Package verification failed\naccess_token=VERIFY_SECRET"

        with self.assertRaisesRegex(ValueError, "Package verification failed"):
            self.module.verify_download(
                ctx,
                artifact,
                "/mnt/flash/switchapp-1.15.1.swix",
            )

        self.assertEqual(
            self.log_events(ctx),
            [
                ("EOS package verification", "STARTED"),
                ("EOS package verification", "ERROR"),
            ],
        )
        log_text = "\n".join(ctx.infos)
        self.assertIn("access_token=<redacted>", log_text)
        self.assertNotIn("VERIFY_SECRET", log_text)
        self.assertNotIn("Status: SUCCESS", log_text)

    def test_swi_verify_download_uses_eos_verify_even_with_sha512_metadata(self):
        artifact = self.module.Artifact(
            name="EOS-4.28.13.1M.swi",
            filename="EOS-4.28.13.1M.swi",
            file_server_path="software/uuid/EOS-4.28.13.1M.swi",
            sha512="repository-digest",
        )
        ctx = FakeCtx({}, {})
        ctx.existing_size = 4096
        ctx.verify_response = (
            "Verifying flash:test/EOS-4.28.13.1M.swi successful."
        )

        self.module.verify_download(
            ctx,
            artifact,
            "/mnt/flash/test/EOS-4.28.13.1M.swi",
        )

        commands = "\n".join(ctx.commands)
        self.assertIn("verify flash:test/EOS-4.28.13.1M.swi", commands)
        self.assertNotIn("sha512sum", commands)
        self.assertEqual(
            ctx.infos,
            [
                "Step: EOS image verification | Status: STARTED | "
                "Artifact: EOS-4.28.13.1M.swi; "
                "Destination: /mnt/flash/test/EOS-4.28.13.1M.swi; "
                "Device verify command: verify flash:test/EOS-4.28.13.1M.swi",
                "Step: EOS image verification | Status: SUCCESS | "
                "Artifact: EOS-4.28.13.1M.swi; "
                "Destination: /mnt/flash/test/EOS-4.28.13.1M.swi; "
                "Device response: Verifying flash:test/EOS-4.28.13.1M.swi successful.",
            ],
        )

    def test_swi_verify_download_accepts_empty_success_response(self):
        artifact = self.module.Artifact(
            name="EOS-4.34.6M.swi",
            filename="EOS-4.34.6M.swi",
            file_server_path="software/uuid/EOS-4.34.6M.swi",
        )
        ctx = FakeCtx({}, {})
        ctx.existing_size = 4096
        ctx.verify_response = ""

        self.module.verify_download(
            ctx,
            artifact,
            "/mnt/flash/EOS-4.34.6M.swi",
        )

        self.assertIn("verify flash:EOS-4.34.6M.swi", "\n".join(ctx.commands))
        self.assertEqual(
            ctx.infos,
            [
                "Step: EOS image verification | Status: STARTED | "
                "Artifact: EOS-4.34.6M.swi; "
                "Destination: /mnt/flash/EOS-4.34.6M.swi; "
                "Device verify command: verify flash:EOS-4.34.6M.swi",
                "Step: EOS image verification | Status: SUCCESS | "
                "Artifact: EOS-4.34.6M.swi; "
                "Destination: /mnt/flash/EOS-4.34.6M.swi; "
                "Device response: (none; absence of Command API error confirms success).",
            ],
        )

    def test_swi_verify_download_rejects_command_error(self):
        artifact = self.module.Artifact(
            name="EOS-4.34.6M.swi",
            filename="EOS-4.34.6M.swi",
            file_server_path="software/uuid/EOS-4.34.6M.swi",
        )
        ctx = FakeCtx({}, {})
        ctx.existing_size = 4096
        ctx.verify_error = "Image verification failed\naccess_token=VERIFY_SECRET"

        with self.assertRaisesRegex(ValueError, "Image verification failed"):
            self.module.verify_download(
                ctx,
                artifact,
                "/mnt/flash/EOS-4.34.6M.swi",
            )

        self.assertEqual(
            self.log_events(ctx),
            [
                ("EOS image verification", "STARTED"),
                ("EOS image verification", "ERROR"),
            ],
        )
        log_text = "\n".join(ctx.infos)
        self.assertIn("access_token=<redacted>", log_text)
        self.assertNotIn("VERIFY_SECRET", log_text)
        self.assertNotIn("Status: SUCCESS", log_text)

    def test_swi_verify_download_redacts_token_from_device_response_log(self):
        artifact = self.module.Artifact(
            name="EOS-4.34.6M.swi",
            filename="EOS-4.34.6M.swi",
            file_server_path="software/uuid/EOS-4.34.6M.swi",
        )
        ctx = FakeCtx({}, {})
        ctx.existing_size = 4096
        ctx.verify_response = "checked access_token=SECRET\nall good"

        self.module.verify_download(
            ctx,
            artifact,
            "/mnt/flash/EOS-4.34.6M.swi",
        )

        log_text = "\n".join(ctx.infos)
        self.assertIn("Device response: checked access_token=<redacted> all good", log_text)
        self.assertNotIn("SECRET", log_text)

    def test_rpm_verify_download_does_not_log_eos_verification(self):
        artifact = self.module.Artifact(
            name="fabric-health-agent-1.0.rpm",
            filename="fabric-health-agent-1.0.rpm",
            file_server_path="software/uuid/fabric-health-agent-1.0.rpm",
            sha512="abc123",
        )
        ctx = FakeCtx({}, {})
        ctx.existing_size = 4096
        ctx.checksum_response = "abc123  /mnt/flash/fabric-health-agent-1.0.rpm"

        self.module.verify_download(
            ctx,
            artifact,
            "/mnt/flash/fabric-health-agent-1.0.rpm",
        )

        self.assertEqual(
            self.log_events(ctx),
            [
                ("Checksum verification", "STARTED"),
                ("Checksum verification", "SUCCESS"),
            ],
        )
        self.assertFalse(any(
            message.startswith((
                "Step: EOS image verification | ",
                "Step: EOS package verification | ",
            ))
            for message in ctx.infos
        ))

    def test_target_is_verified_uses_eos_verify_for_swi(self):
        artifact = self.module.Artifact(
            name="EOS-4.34.7M.swi",
            filename="EOS-4.34.7M.swi",
            file_server_path="software/uuid/EOS-4.34.7M.swi",
        )
        ctx = FakeCtx({}, {})
        ctx.existing_size = 4096

        verified = self.module.target_is_verified(
            ctx,
            artifact,
            "/mnt/flash/EOS-4.34.7M.swi",
            existing_size=4096,
        )

        self.assertTrue(verified)
        self.assertIn("verify flash:EOS-4.34.7M.swi", "\n".join(ctx.commands))
        self.assertEqual(ctx.infos, [])

    def test_target_is_verified_swix_success_and_failure_do_not_checksum(self):
        cases = (
            ("TerminAttr-1.40.10-1.swix", "sha512", "", True),
            ("fabric-health-agent-1.0.SWIX", "md5", "verification failed", False),
        )
        for filename, digest_field, verify_error, expected in cases:
            with self.subTest(filename=filename):
                artifact = self.module.Artifact(
                    name=filename,
                    filename=filename,
                    file_server_path=f"software/uuid/{filename}",
                    **{digest_field: "repository-digest"},
                )
                ctx = FakeCtx({}, {})
                ctx.verify_error = verify_error

                verified = self.module.target_is_verified(
                    ctx,
                    artifact,
                    f"/mnt/flash/{filename}",
                    existing_size=4096,
                )

                commands = "\n".join(ctx.commands)
                self.assertEqual(verified, expected)
                self.assertIn(f"verify flash:{filename}", commands)
                self.assertNotIn("sha512sum", commands)
                self.assertNotIn("md5sum", commands)

    def test_target_is_verified_reads_rpm_when_digest_is_unavailable(self):
        artifact = self.module.Artifact(
            name="fabric-health-agent-1.0.rpm",
            filename="fabric-health-agent-1.0.rpm",
            file_server_path="software/uuid/fabric-health-agent-1.0.rpm",
        )
        ctx = FakeCtx({}, {})
        ctx.existing_size = 4096

        verified = self.module.target_is_verified(
            ctx,
            artifact,
            "/mnt/flash/fabric-health-agent-1.0.rpm",
            existing_size=4096,
        )

        self.assertTrue(verified)
        self.assertIn("md5sum", "\n".join(ctx.commands))

    def test_target_is_verified_rejects_rpm_checksum_mismatch(self):
        artifact = self.module.Artifact(
            name="fabric-health-agent-1.0.rpm",
            filename="fabric-health-agent-1.0.rpm",
            file_server_path="software/uuid/fabric-health-agent-1.0.rpm",
            md5="expected",
        )
        ctx = FakeCtx({}, {})
        ctx.existing_size = 4096
        ctx.checksum_response = "actual  /mnt/flash/EOS-4.34.7M.swi"

        verified = self.module.target_is_verified(
            ctx,
            artifact,
            "/mnt/flash/fabric-health-agent-1.0.rpm",
            existing_size=4096,
        )

        self.assertFalse(verified)

    def test_remove_existing_target_only_removes_destination(self):
        ctx = FakeCtx({}, {})

        self.module.remove_existing_target(ctx, "/mnt/flash/EOS-4.34.7M.swi")

        command = ctx.commands[-1]
        self.assertIn("/mnt/flash/EOS-4.34.7M.swi", command)
        self.assertNotIn(".studio-image-preload", command)

    def test_non_swi_preload_command_downloads_without_swadapt(self):
        command = self.module.render_file_preload_command(
            "https://api.example/api/v1/files/software/id/TerminAttr.swix",
            "/mnt/flash/TerminAttr.swix",
            "MGMT",
            "192.0.2.112",
            "token",
        )

        payload = bash_payload(command)
        self.assertIn("--output /mnt/flash/TerminAttr.swix", payload)
        self.assertNotIn("/export/swi/swadapt", payload)

    def test_directory_destination_appends_artifact_filename(self):
        artifact = self.module.Artifact(
            name="EOS-4.28.13.1M.swi",
            filename="EOS-4.28.13.1M.swi",
            file_server_path="software/uuid/EOS-4.28.13.1M.swi",
        )

        destination = self.module.destination_for_artifact(
            artifact,
            "/mnt/flash/test/",
            0,
        )

        self.assertEqual(destination, "/mnt/flash/test/EOS-4.28.13.1M.swi")

    def test_helper_bash_commands_use_command_api_timeout_wrapper(self):
        artifact = self.module.Artifact(
            name="EOS-4.34.7M.swi",
            filename="EOS-4.34.7M.swi",
            file_server_path="software/uuid/EOS-4.34.7M.swi",
        )
        ctx = FakeCtx({}, {})
        ctx.existing_size = 4096

        self.module.detect_vrf(ctx, "192.0.2.112")
        self.module.get_existing_size(ctx, "/mnt/flash/EOS-4.34.7M.swi")
        self.module.remove_existing_target(ctx, "/mnt/flash/EOS-4.34.7M.swi")
        self.module.target_is_verified(
            ctx,
            artifact,
            "/mnt/flash/EOS-4.34.7M.swi",
            existing_size=4096,
        )

        for command in ctx.commands:
            if command.startswith("bash"):
                self.assertRegex(command, r"^bash timeout (120|3597) bash -c ")

    def test_repository_source_treats_trailing_slash_destination_as_directory(self):
        ctx = self.resource_ctx(
            {
                "DeviceID": "JPE00000001",
                "Source": "repository",
                "Repository Image": "EOS-4.28.13.1M.swi",
                "Destination": "/mnt/flash/test/",
                "VRF": "MGMT",
                "Force": "False",
            },
            repository_config=[
                {
                    "result": {
                        "value": {
                            "key": {"name": "EOS-4.28.13.1M.swi"},
                            "uri": (
                                "/software/repository-directory-image/"
                                "EOS-4.28.13.1M.swi"
                            ),
                        }
                    }
                }
            ],
            provisioned_device={"JPE00000001": self.provisioned_device()},
        )

        self.module.run(ctx)

        self.assert_structured_logs(ctx)
        transfer = "\n".join(ctx.commands)
        self.assertIn("mkdir -p -- /mnt/flash/test", transfer)
        self.assertIn(
            "/export/swi/swadapt /mnt/flash/test/EOS-4.28.13.1M.swi",
            transfer,
        )
        self.assertNotIn("/export/swi/swadapt /mnt/flash/test/'", transfer)
        self.assertTrue(any(
            "Step: EOS image verification | Status: STARTED | " in message
            and "Device verify command: verify flash:test/EOS-4.28.13.1M.swi" in message
            for message in ctx.infos
        ))

    def test_run_rewrite_logs_warning_and_cleanup_outcome(self):
        ctx = self.resource_ctx(
            {
                "DeviceID": "JPE00000001",
                "Source": "repository",
                "Repository Image": "EOS-4.34.6M.swi",
                "VRF": "MGMT",
                "Force": "True",
            },
            repository_config=[self.repository_config_records()[0]],
            provisioned_device={"JPE00000001": self.provisioned_device()},
        )
        ctx.existing_size = 4096

        self.module.run(ctx)

        self.assert_structured_logs(ctx)
        self.assertEqual(
            self.log_events(ctx),
            [
                ("Artifact preload", "STARTED"),
                ("Existing target handling", "WARNING"),
                ("Existing target cleanup", "STARTED"),
                ("Existing target cleanup", "SUCCESS"),
                ("Artifact transfer", "STARTED"),
                ("Artifact transfer", "SUCCESS"),
                ("EOS image verification", "STARTED"),
                ("EOS image verification", "SUCCESS"),
                ("Artifact preload", "SUCCESS"),
            ],
        )
        self.assertIn("Reason: force requested", ctx.infos[1])

    def test_run_cleanup_failure_logs_sanitized_errors_and_reraises_same_exception(self):
        ctx = self.resource_ctx(
            {
                "DeviceID": "JPE00000001",
                "Source": "repository",
                "Repository Image": "EOS-4.34.6M.swi",
                "VRF": "MGMT",
                "Force": "True",
            },
            repository_config=[self.repository_config_records()[0]],
            provisioned_device={"JPE00000001": self.provisioned_device()},
        )
        ctx.existing_size = 4096
        error = RuntimeError(
            "cleanup failed\naccess_token=CLEANUP_SECRET " + ("x" * 1000)
        )
        ctx.cleanup_exception = error

        with self.assertRaises(RuntimeError) as raised:
            self.module.run(ctx)

        self.assertIs(raised.exception, error)
        self.assert_structured_logs(ctx)
        self.assertEqual(
            self.log_events(ctx),
            [
                ("Artifact preload", "STARTED"),
                ("Existing target handling", "WARNING"),
                ("Existing target cleanup", "STARTED"),
                ("Existing target cleanup", "ERROR"),
                ("Artifact preload", "ERROR"),
            ],
        )
        self.assertTrue(any("rm -f --" in command for command in ctx.commands))
        self.assertTrue(any("stat -c %s" in command for command in ctx.commands))
        self.assertFalse(any("md5sum" in command for command in ctx.commands))
        self.assertFalse(any("sha512sum" in command for command in ctx.commands))
        self.assertFalse(ctx.transfer_ran)
        log_text = "\n".join(ctx.infos)
        self.assertIn("access_token=<redacted>", log_text)
        self.assertNotIn("CLEANUP_SECRET", log_text)
        self.assertNotIn("Existing target cleanup | Status: SUCCESS", log_text)
        self.assertNotIn("Artifact transfer", log_text)
        self.assertNotIn("EOS image verification", log_text)
        self.assertNotIn("Status: SUCCESS", log_text)
        error_details = [
            message.split(" | ", 2)[-1]
            for message in ctx.infos
            if " | Status: ERROR | " in message
        ]
        self.assertTrue(all("\n" not in detail for detail in error_details))
        self.assertTrue(all(len(detail) <= 500 for detail in error_details))
        self.assertTrue(all(detail.endswith("...[truncated]") for detail in error_details))

    def test_run_logs_transfer_and_verification_in_execution_order(self):
        ctx = self.resource_ctx(
            {
                "DeviceID": "JPE00000001",
                "Source": "repository",
                "Repository Image": "EOS-4.34.6M.swi",
                "VRF": "MGMT",
                "Force": "False",
            },
            repository_config=[self.repository_config_records()[0]],
            provisioned_device={"JPE00000001": self.provisioned_device()},
        )

        self.module.run(ctx)

        self.assert_structured_logs(ctx)
        self.assertEqual(
            self.log_events(ctx),
            [
                ("Artifact preload", "STARTED"),
                ("Artifact transfer", "STARTED"),
                ("Artifact transfer", "SUCCESS"),
                ("EOS image verification", "STARTED"),
                ("EOS image verification", "SUCCESS"),
                ("Artifact preload", "SUCCESS"),
            ],
        )
        self.assertIn(
            "Repository path: software/repository-image/EOS-4.34.6M.swi",
            ctx.infos[0],
        )
        self.assertNotIn("Source: software/repository-image", ctx.infos[0])
        transfer_start = ctx.infos[1]
        self.assertIn("Artifact: EOS-4.34.6M.swi", transfer_start)
        self.assertIn(
            "Source: https://api.example/api/v1/files/software/repository-image/"
            "EOS-4.34.6M.swi",
            transfer_start,
        )
        self.assertIn("Destination: /mnt/flash/EOS-4.34.6M.swi", transfer_start)
        artifact = self.module.Artifact(
            name="EOS-4.34.6M.swi",
            filename="EOS-4.34.6M.swi",
            file_server_path="software/repository-image/EOS-4.34.6M.swi",
        )
        redacted_command = self.module.render_artifact_preload_command(
            artifact,
            "https://api.example/api/v1/files/software/repository-image/EOS-4.34.6M.swi",
            "/mnt/flash/EOS-4.34.6M.swi",
            "MGMT",
            "192.0.2.221",
            "secret-token",
            redacted=True,
        )
        self.assertTrue(transfer_start.endswith(
            f"Device transfer command: {redacted_command}"
        ))
        self.assertIn("access_token=<redacted>", transfer_start)
        self.assertNotIn("secret-token", "\n".join(ctx.infos))

    def test_run_uppercase_swi_uses_swadapt_and_eos_verification(self):
        filename = "EOS-4.34.7M.SWI"
        ctx = self.resource_ctx(
            {
                "DeviceID": "JPE00000001",
                "Source": "repository",
                "Repository Image": filename,
                "VRF": "MGMT",
                "Force": "False",
            },
            repository_config=self.repository_artifact_records([filename]),
            provisioned_device={"JPE00000001": self.provisioned_device()},
        )

        self.module.run(ctx)

        transfers = [
            command for command in ctx.commands
            if "curl " in command and ("swadapt" in command or "--output" in command)
        ]
        self.assertEqual(len(transfers), 1)
        self.assertIn("/export/swi/swadapt /mnt/flash/EOS-4.34.7M.SWI", transfers[0])
        self.assertNotIn("--output", transfers[0])
        self.assertIn("verify flash:EOS-4.34.7M.SWI", ctx.commands)
        self.assertIn(
            ("EOS image verification", "SUCCESS"),
            self.log_events(ctx),
        )

    def test_run_verify_error_logs_attempt_without_completion_or_preloaded(self):
        ctx = self.resource_ctx(
            {
                "DeviceID": "JPE00000001",
                "Source": "repository",
                "Repository Image": "EOS-4.34.6M.swi",
                "VRF": "MGMT",
                "Force": "False",
            },
            repository_config=[self.repository_config_records()[0]],
            provisioned_device={"JPE00000001": self.provisioned_device()},
        )
        ctx.verify_error = "Image verification failed\naccess_token=VERIFY_SECRET"

        with self.assertRaisesRegex(ValueError, "Image verification failed"):
            self.module.run(ctx)

        self.assert_structured_logs(ctx)
        self.assertEqual(
            self.log_events(ctx),
            [
                ("Artifact preload", "STARTED"),
                ("Artifact transfer", "STARTED"),
                ("Artifact transfer", "SUCCESS"),
                ("EOS image verification", "STARTED"),
                ("EOS image verification", "ERROR"),
                ("Artifact preload", "ERROR"),
            ],
        )
        log_text = "\n".join(ctx.infos)
        self.assertNotIn("VERIFY_SECRET", log_text)
        self.assertNotIn("Status: SUCCESS | Artifact: EOS-4.34.6M.swi; Destination", log_text)

    def test_run_transfer_failure_logs_sanitized_errors_and_reraises_same_exception(self):
        ctx = self.resource_ctx(
            {
                "DeviceID": "JPE00000001",
                "Source": "repository",
                "Repository Image": "EOS-4.34.6M.swi",
                "VRF": "MGMT",
                "Force": "False",
            },
            repository_config=[self.repository_config_records()[0]],
            provisioned_device={"JPE00000001": self.provisioned_device()},
        )
        error = RuntimeError(
            "transfer failed\naccess_token=TRANSFER_SECRET " + ("x" * 1000)
        )
        ctx.transfer_exception = error

        with self.assertRaises(RuntimeError) as raised:
            self.module.run(ctx)

        self.assertIs(raised.exception, error)
        self.assert_structured_logs(ctx)
        self.assertEqual(
            self.log_events(ctx),
            [
                ("Artifact preload", "STARTED"),
                ("Artifact transfer", "STARTED"),
                ("Artifact transfer", "ERROR"),
                ("Artifact preload", "ERROR"),
            ],
        )
        log_text = "\n".join(ctx.infos)
        self.assertIn("access_token=<redacted>", log_text)
        self.assertNotIn("TRANSFER_SECRET", log_text)
        self.assertNotIn("Status: SUCCESS", log_text)
        error_details = [
            message.split(" | ", 2)[-1]
            for message in ctx.infos
            if " | Status: ERROR | " in message
        ]
        self.assertTrue(all(len(detail) <= 500 for detail in error_details))
        self.assertTrue(all(detail.endswith("...[truncated]") for detail in error_details))

    def test_run_idempotency_skip_does_not_log_post_transfer_verification(self):
        ctx = self.resource_ctx(
            {
                "DeviceID": "JPE00000001",
                "Source": "repository",
                "Repository Image": "EOS-4.34.6M.swi",
                "VRF": "MGMT",
                "Force": "False",
            },
            repository_config=[self.repository_config_records()[0]],
            provisioned_device={"JPE00000001": self.provisioned_device()},
        )
        ctx.existing_size = 4096

        self.module.run(ctx)

        self.assert_structured_logs(ctx)
        self.assertEqual(
            self.log_events(ctx),
            [
                ("Artifact preload", "STARTED"),
                ("Artifact preload", "SKIPPED"),
            ],
        )
        self.assertIn("Reason: target file already verifies", ctx.infos[1])
        self.assertFalse(any(
            message.startswith("Step: EOS image verification | ")
            for message in ctx.infos
        ))

    def test_run_existing_verified_swix_is_skipped_without_checksum(self):
        names = ["EOS-4.34.6M.swi", "switchapp-1.15.1.swix"]
        ctx = self.repository_artifacts_context(
            {
                "DeviceID": "JPE00000001",
                "Source": "repository",
                "Repository Image": names[0],
                "Repository Extensions": names[1],
                "VRF": "MGMT",
                "Force": "False",
            },
            names,
        )
        ctx.existing_sizes[f"/mnt/flash/{names[1]}"] = 4096

        self.module.run(ctx)

        transfers = [command for command in ctx.commands if "curl " in command]
        commands = "\n".join(ctx.commands)
        self.assertEqual(len(transfers), 1)
        self.assertIn(names[0], transfers[0])
        self.assertNotIn(names[1], transfers[0])
        self.assertIn(f"verify flash:{names[1]}", commands)
        self.assertNotIn("sha512sum", commands)
        self.assertNotIn("md5sum", commands)
        self.assertEqual(
            self.log_events(ctx)[-2:],
            [
                ("Artifact preload", "STARTED"),
                ("Artifact preload", "SKIPPED"),
            ],
        )
        self.assertIn(names[1], ctx.infos[-1])
        self.assertIn("target file already verifies", ctx.infos[-1])
        self.assertNotIn("EOS package verification", "\n".join(ctx.infos))

    def test_run_existing_swix_failed_verify_rewrites_and_reverifies(self):
        names = ["EOS-4.34.6M.swi", "switchapp-1.15.1.swix"]
        ctx = self.repository_artifacts_context(
            {
                "DeviceID": "JPE00000001",
                "Source": "repository",
                "Repository Image": names[0],
                "Repository Extensions": names[1],
                "VRF": "MGMT",
                "Force": "False",
            },
            names,
        )
        destination = f"/mnt/flash/{names[1]}"
        verify_command = f"verify flash:{names[1]}"
        ctx.existing_sizes[destination] = 4096
        ctx.verify_errors[verify_command] = ["existing package verification failed"]

        self.module.run(ctx)

        commands = "\n".join(ctx.commands)
        transfers = [command for command in ctx.commands if "curl " in command]
        self.assertEqual(ctx.commands.count(verify_command), 2)
        self.assertEqual(len(transfers), 2)
        self.assertIn(f"--output {destination}", transfers[-1])
        self.assertNotIn("/export/swi/swadapt", transfers[-1])
        self.assertIn(f"rm -f -- {destination}", commands)
        self.assertNotIn("sha512sum", commands)
        self.assertNotIn("md5sum", commands)
        events = self.log_events(ctx)
        self.assertIn(("Existing target handling", "WARNING"), events)
        self.assertIn(("Existing target cleanup", "SUCCESS"), events)
        self.assertIn(("EOS package verification", "STARTED"), events)
        self.assertIn(("EOS package verification", "SUCCESS"), events)
        self.assertEqual(events[-1], ("Artifact preload", "SUCCESS"))

    def test_default_is_honored_as_explicit_value(self):
        self.assertEqual(self.module.auto_arg("default"), "default")

    def test_pure_device_selector_lists_parse_without_api(self):
        matching = (
            " device:JPE00000001 ",
            "device:JPE00000002 | device:JPE00000001",
            "device:JPE00000002 or device:JPE00000001",
            "device: JPE00000002, JPE00000001",
            "device:JPE00000002,JPE00000003 OR device:JPE00000001",
        )
        nonmatching = (
            "device:JPE00000002",
            "device:JPE00000002 | device:JPE00000003",
            "device:JPE00000002 Or device:JPE00000003",
            "device: JPE00000002, JPE00000003",
            "device:JPE00000002,JPE00000003 | device:JPE00000004",
        )
        for query in matching:
            with self.subTest(query=query, matches=True):
                self.assertIn(
                    "JPE00000001",
                    self.module.pure_device_query_ids(query.strip()),
                )
        for query in nonmatching:
            with self.subTest(query=query, matches=False):
                self.assertNotIn(
                    "JPE00000001",
                    self.module.pure_device_query_ids(query.strip()),
                )
        self.assertIsNone(self.module.pure_device_query_ids("tag:site:example"))

    def test_committed_mainline_record_wins_over_stale_workspace_draft(self):
        image = "EOS-4.34.6M.swi"
        agent = "TerminAttr-1.40.10-1.swix"
        stale = self.studio_software_inputs_record(
            image="EOS-4.35.4M.swi",
            agent=None,
            extensions=(),
            workspace_id="workspace-draft",
            path={},
        )
        mainline = self.studio_software_inputs_record(
            image=image,
            agent=agent,
            extensions=(),
            query="device:JPE00000001 | device:JPE00000002",
            path={},
        )
        ctx = self.resource_ctx(
            {
                "DeviceID": "JPE00000001",
                "Source": "designed",
                "VRF": "MGMT",
                "Force": "False",
            },
            repository_config=self.designed_repository_config_records(),
            studio_inputs=[stale, mainline],
            provisioned_device={"JPE00000001": self.provisioned_device()},
        )

        self.module.run(ctx)

        transfers = [
            command for command in ctx.commands
            if "curl " in command
            and ("/export/swi/swadapt" in command or "--output" in command)
        ]
        self.assertEqual(len(transfers), 2)
        self.assertIn(image, transfers[0])
        self.assertIn(agent, transfers[1])
        self.assertNotIn("EOS-4.35.4M.swi", "\n".join(transfers))
        self.assertEqual(
            self.designed_resolution_logs(ctx),
            [
                "Step: Designed resolution | Status: SUCCESS | "
                "Software Assignment: matched committed mainline assignment for "
                "JPE00000001; "
                f"Image decision: {image} configured; include {image}; "
                f"Streaming agent decision: external {agent} configured; "
                f"include {agent}; "
                "Extensions decision: 0 configured; no extension artifacts included; "
                f"Final: {image} (image), {agent} (agent)"
            ],
        )

    def test_state_mainline_fragments_concatenate_across_json_tokens(self):
        image = "EOS-4.34.6M.swi"
        agent = "TerminAttr-1.40.10-1.swix"
        extension = "switchapp-1.15.1-1.10.swix"
        payload = json.dumps({
            "softwareResolver": [{
                "inputs": {"softwareGroup": {
                    "imageName": image,
                    "streamingAgentName": agent,
                    "extensionsCollection": [
                        {"extensionName": extension},
                    ],
                }},
                "tags": {"query": "device:JPE00000001 | device:JPE00000002"},
            }],
        })
        cuts = (
            payload.index("softwareResolver") + 5,
            payload.index("streamingAgentName") + 9,
            payload.index(agent) + 8,
            payload.index("extensionName") + 7,
        )
        ctx = self.resource_ctx(
            {},
            repository_config=self.designed_repository_config_records(),
            studio_inputs=self.studio_inputs_fragments(payload, cuts),
        )

        selected = self.module.resolve_runtime_artifacts(
            ctx, "designed", "JPE00000001", ""
        )

        self.assertEqual(
            [artifact.filename for artifact in selected],
            [image, agent, extension],
        )
        self.assertEqual(ctx.studio_inputs_config_client.calls, 0)

    def test_inputs_config_fragments_fallback_and_preserve_extension_order(self):
        image = "EOS-4.34.6M.swi"
        extension_a = "extension-a.swix"
        extension_b = "extension-b.rpm"
        payload = json.dumps({
            "softwareResolver": [{
                "inputs": {"softwareGroup": {
                    "imageName": image,
                    "streamingAgentName": "",
                    "extensionsCollection": [
                        {"extensionName": extension_a},
                        {"extensionName": extension_b},
                    ],
                }},
                "tags": {"query": "device:JPE00000001"},
            }],
        })
        cuts = (
            payload.index("imageName") + 4,
            payload.index(extension_a) + 6,
            payload.index("extensionName", payload.index(extension_a)) + 8,
            payload.index(extension_b) + 5,
        )
        cuts = tuple(sorted(cuts))
        ctx = self.resource_ctx(
            {},
            repository_config=(
                [self.repository_config_records()[0]]
                + self.repository_artifact_records([extension_b, extension_a])
            ),
            studio_inputs=[],
            studio_inputs_config=self.studio_inputs_fragments(payload, cuts),
        )

        selected = self.module.resolve_runtime_artifacts(
            ctx, "designed", "JPE00000001", ""
        )

        self.assertEqual(
            [artifact.filename for artifact in selected],
            [image, extension_a, extension_b],
        )
        self.assertEqual(ctx.studio_inputs_client.calls, 1)
        self.assertEqual(ctx.studio_inputs_config_client.calls, 1)
        self.assertIn(
            "Extensions decision: 2 configured; "
            f"include {extension_a}, {extension_b}",
            self.designed_resolution_logs(ctx)[0],
        )

    def test_duplicate_complete_or_malformed_mainline_fragments_fail(self):
        complete_a = self.studio_software_inputs_record(
            agent="", extensions=(), path={}
        )
        complete_b = self.studio_software_inputs_record(
            image="EOS-4.35.4M.swi", agent="", extensions=(),
            path={"values": []},
        )
        malformed = self.studio_inputs_fragments(
            '{"softwareResolver":[access_token=fragment-secret',
            (7, 29),
        )
        cases = (
            ("duplicate complete", [complete_a, complete_b], "multiple"),
            ("malformed fragments", malformed, "malformed fragment"),
        )
        for label, records, marker in cases:
            with self.subTest(label=label):
                ctx = self.resource_ctx(
                    {
                        "DeviceID": "JPE00000001",
                        "Source": "designed",
                        "VRF": "MGMT",
                        "Force": "False",
                    },
                    repository_config=self.repository_config_records()[:2],
                    studio_inputs=records,
                    provisioned_device={"JPE00000001": self.provisioned_device()},
                )

                with self.assertRaises(ValueError) as raised:
                    self.module.run(ctx)

                self.assertIn(marker, str(raised.exception).casefold())
                self.assertNotIn("fragment-secret", str(raised.exception))
                self.assertEqual(ctx.commands, [])
                self.assertEqual(self.designed_resolution_logs(ctx), [])

    def test_state_mainline_is_preferred_over_conflicting_config_mainline(self):
        state = self.studio_software_inputs_record(
            agent="",
            extensions=(),
            path={},
        )
        config = self.studio_software_inputs_record(
            image="EOS-4.35.4M.swi",
            agent="",
            extensions=(),
            path={"values": []},
        )
        ctx = self.resource_ctx(
            {},
            repository_config=self.repository_config_records()[:2],
            studio_inputs=[state],
            studio_inputs_config=[config],
        )

        selected = self.module.resolve_runtime_artifacts(
            ctx, "designed", "JPE00000001", ""
        )

        self.assertEqual(
            [artifact.filename for artifact in selected],
            ["EOS-4.34.6M.swi"],
        )
        self.assertEqual(ctx.studio_inputs_client.calls, 1)
        self.assertEqual(ctx.studio_inputs_config_client.calls, 0)

    def test_config_mainline_fallback_works_for_unavailable_or_empty_state(self):
        config = self.studio_software_inputs_record(
            agent="",
            extensions=(),
            path={"values": []},
        )
        state_cases = (
            ("unavailable", None),
            (
                "no mainline",
                [self.studio_software_inputs_record(
                    agent=None,
                    extensions=(),
                    workspace_id="draft",
                    path={},
                )],
            ),
        )
        for label, state_records in state_cases:
            with self.subTest(label=label):
                ctx = self.resource_ctx(
                    {},
                    repository_config=[self.repository_config_records()[0]],
                    studio_inputs=state_records,
                    studio_inputs_config=[config],
                )

                selected = self.module.resolve_runtime_artifacts(
                    ctx, "designed", "JPE00000001", ""
                )

                self.assertEqual(
                    [artifact.filename for artifact in selected],
                    ["EOS-4.34.6M.swi"],
                )
                self.assertEqual(ctx.studio_inputs_client.calls, 1)
                self.assertEqual(ctx.studio_inputs_config_client.calls, 1)

    def test_mainline_filter_ignores_drafts_other_studios_and_non_root_paths(self):
        null_path = self.studio_software_inputs_record(
            path={}, agent=None, extensions=()
        )
        null_path["value"]["key"]["path"] = None
        records = [
            self.studio_software_inputs_record(
                workspace_id="draft", path={}, agent=None, extensions=()
            ),
            self.studio_software_inputs_record(
                studio_id="other-studio", path={}, agent=None, extensions=()
            ),
            self.studio_software_inputs_record(
                workspace_id=" ", path={}, agent=None, extensions=()
            ),
            self.studio_software_inputs_record(
                studio_id=" studio-software-management ",
                path={},
                agent=None,
                extensions=(),
            ),
            self.studio_software_inputs_record(
                path={"values": ["nested"]}, agent=None, extensions=()
            ),
            null_path,
            self.studio_software_inputs_record(
                path={"values": []}, agent="", extensions=()
            ),
        ]
        ctx = self.resource_ctx(
            {},
            repository_config=[self.repository_config_records()[0]],
            studio_inputs=records,
        )

        selected = self.module.resolve_runtime_artifacts(
            ctx, "designed", "JPE00000001", ""
        )

        self.assertEqual(
            [artifact.filename for artifact in selected],
            ["EOS-4.34.6M.swi"],
        )

    def test_missing_or_duplicate_mainline_root_fails(self):
        duplicate = self.studio_software_inputs_record(
            agent="", extensions=(), path={}
        )
        cases = (
            (
                "missing",
                [self.studio_software_inputs_record(
                    workspace_id="draft", agent=None, extensions=(), path={}
                )],
                [],
                "mainline",
            ),
            (
                "duplicate",
                [duplicate, duplicate],
                [duplicate],
                "multiple",
            ),
        )
        for label, state, config, marker in cases:
            with self.subTest(label=label):
                ctx = self.resource_ctx(
                    {},
                    repository_config=[self.repository_config_records()[0]],
                    studio_inputs=state,
                    studio_inputs_config=config,
                )

                with self.assertRaises(ValueError) as raised:
                    self.module.resolve_runtime_artifacts(
                        ctx, "designed", "JPE00000001", ""
                    )

                self.assertIn(marker, str(raised.exception).casefold())
                self.assertEqual(ctx.commands, [])
                self.assertEqual(self.designed_resolution_logs(ctx), [])
                if label == "duplicate":
                    self.assertEqual(ctx.studio_inputs_config_client.calls, 0)

    def test_embedded_null_and_empty_agent_include_only_image_with_explicit_log(self):
        image = "EOS-4.34.6M.swi"
        for agent in (None, ""):
            with self.subTest(agent=agent):
                ctx = self.resource_ctx(
                    {},
                    repository_config=[self.repository_config_records()[0]],
                    studio_inputs=[self.studio_software_inputs_record(
                        agent=agent,
                        extensions=(),
                        path={},
                    )],
                )

                selected = self.module.resolve_runtime_artifacts(
                    ctx, "designed", "JPE00000001", ""
                )

                self.assertEqual([artifact.filename for artifact in selected], [image])
                diagnostic = self.designed_resolution_logs(ctx)
                self.assertEqual(len(diagnostic), 1)
                self.assertIn(
                    "Streaming agent decision: embedded configured; "
                    "no separate streaming-agent artifact included",
                    diagnostic[0],
                )
                self.assertIn(
                    "Extensions decision: 0 configured; "
                    "no extension artifacts included",
                    diagnostic[0],
                )
                self.assertNotIn("none resolved", diagnostic[0])

    def test_configured_extensions_preserve_order_and_log_count(self):
        extension_a = "extension-a.swix"
        extension_b = "extension-b.rpm"
        repository = (
            [self.repository_config_records()[0]]
            + self.repository_artifact_records([extension_b, extension_a])
        )
        cases = (
            ((extension_a,), [extension_a]),
            ((extension_a, extension_b), [extension_a, extension_b]),
        )
        for extensions, expected_extensions in cases:
            with self.subTest(extensions=extensions):
                ctx = self.resource_ctx(
                    {},
                    repository_config=repository,
                    studio_inputs=[self.studio_software_inputs_record(
                        agent="",
                        extensions=extensions,
                        path={},
                    )],
                )

                selected = self.module.resolve_runtime_artifacts(
                    ctx, "designed", "JPE00000001", ""
                )

                self.assertEqual(
                    [artifact.filename for artifact in selected],
                    ["EOS-4.34.6M.swi"] + expected_extensions,
                )
                diagnostic = self.designed_resolution_logs(ctx)[0]
                self.assertIn(
                    f"Extensions decision: {len(extensions)} configured; "
                    f"include {', '.join(expected_extensions)}",
                    diagnostic,
                )

    def test_malformed_software_settings_fail_before_device_command(self):
        base_group = {
            "imageName": "EOS-4.34.6M.swi",
            "streamingAgentName": "",
            "extensionsCollection": [],
        }
        malformed_groups = []
        for field in ("streamingAgentName", "extensionsCollection", "imageName"):
            group = dict(base_group)
            del group[field]
            malformed_groups.append((f"missing {field}", group, field))
        malformed_groups.extend((
            (
                "non-string agent",
                dict(base_group, streamingAgentName=7),
                "streamingAgentName",
            ),
            (
                "non-list extensions",
                dict(base_group, extensionsCollection="extension.swix"),
                "extensionsCollection",
            ),
            (
                "blank extension",
                dict(base_group, extensionsCollection=[{"extensionName": " "}]),
                "extensionName",
            ),
            (
                "missing extension name",
                dict(base_group, extensionsCollection=[{}]),
                "extensionName",
            ),
            (
                "malformed extension entry",
                dict(base_group, extensionsCollection=["extension.swix"]),
                "extensionName",
            ),
            (
                "non-string extension name",
                dict(base_group, extensionsCollection=[{"extensionName": 7}]),
                "extensionName",
            ),
            (
                "duplicate extension",
                dict(base_group, extensionsCollection=[
                    {"extensionName": "access_token=extension-secret"},
                    {"extensionName": "access_token=extension-secret"},
                ]),
                "duplicate",
            ),
        ))
        for label, software_group, marker in malformed_groups:
            with self.subTest(label=label):
                record = self.studio_software_resolvers_record([
                    {
                        "inputs": {"softwareGroup": software_group},
                        "tags": {"query": "device:JPE00000001"},
                    },
                ], path={})
                ctx = self.resource_ctx(
                    {
                        "DeviceID": "JPE00000001",
                        "Source": "designed",
                        "VRF": "MGMT",
                        "Force": "False",
                    },
                    repository_config=self.designed_repository_config_records(),
                    studio_inputs=[record],
                    provisioned_device={"JPE00000001": self.provisioned_device()},
                )

                with self.assertRaises(ValueError) as raised:
                    self.module.run(ctx)

                self.assertIn(marker, str(raised.exception))
                self.assertNotIn("extension-secret", str(raised.exception))
                self.assertEqual(ctx.commands, [])
                self.assertFalse(ctx.transfer_ran)
                self.assertEqual(self.designed_resolution_logs(ctx), [])

    def test_assignment_no_match_overlap_or_unsupported_selector_fails(self):
        valid_group = {
            "imageName": "EOS-4.34.6M.swi",
            "streamingAgentName": "",
            "extensionsCollection": [],
        }

        def resolver(query):
            return {
                "inputs": {"softwareGroup": valid_group},
                "tags": {"query": query},
            }
        cases = (
            ("no match", [resolver("device:JPE00000002")], "no matching"),
            (
                "overlap",
                [
                    resolver("device:JPE00000001 | device:JPE00000002"),
                    resolver("device:JPE00000001"),
                ],
                "multiple",
            ),
            ("unsupported", [resolver("tag:site:example")], "unsupported"),
        )
        for label, resolvers, marker in cases:
            with self.subTest(label=label):
                ctx = self.resource_ctx(
                    {
                        "DeviceID": "JPE00000001",
                        "Source": "designed",
                        "VRF": "MGMT",
                        "Force": "False",
                    },
                    repository_config=[self.repository_config_records()[0]],
                    studio_inputs=[self.studio_software_resolvers_record(
                        resolvers, path={}
                    )],
                    provisioned_device={"JPE00000001": self.provisioned_device()},
                    tag_query_results={
                        "tag:site:example": [self.tag_element("JPE00000001")],
                    },
                )

                with self.assertRaises(ValueError) as raised:
                    self.module.run(ctx)

                self.assertIn(marker, str(raised.exception).casefold())
                self.assertEqual(ctx.commands, [])
                self.assertEqual(ctx.tag_client.requests, [])
                self.assertEqual(self.designed_resolution_logs(ctx), [])

    def test_unrelated_unsupported_assignment_with_direct_match_fails_offline(self):
        software_group = {
            "imageName": "EOS-4.34.6M.swi",
            "streamingAgentName": "",
            "extensionsCollection": [],
        }
        resolvers = [
            {
                "inputs": {"softwareGroup": software_group},
                "tags": {"query": "Tag: site:example"},
            },
            {
                "inputs": {"softwareGroup": software_group},
                "tags": {"query": "device:JPE00000001"},
            },
        ]
        ctx = self.resource_ctx(
            {
                "DeviceID": "JPE00000001",
                "Source": "designed",
                "VRF": "MGMT",
                "Force": "False",
            },
            repository_config=[self.repository_config_records()[0]],
            studio_inputs=[self.studio_software_resolvers_record(
                resolvers, path={}
            )],
            provisioned_device={"JPE00000001": self.provisioned_device()},
            tag_query_results={
                "Tag: site:example": [self.tag_element("JPE00000001")],
            },
        )

        with self.assertRaisesRegex(ValueError, "unsupported device selector"):
            self.module.run(ctx)

        self.assertEqual(ctx.tag_client.requests, [])
        self.assertEqual(ctx.commands, [])
        self.assertEqual(self.designed_resolution_logs(ctx), [])

    def test_designed_mode_never_calls_assignments_tags_or_image_summary(self):
        ctx = self.resource_ctx(
            {},
            repository_config=self.designed_repository_config_records(),
            assignment_records=[
                self.assignment_record("EOS-4.35.4M.swi", "JPE00000001"),
            ],
            studio_inputs=[self.studio_software_inputs_record(
                extensions=(), path={}
            )],
            image_summary={
                "JPE00000001": {
                    "value": {"b": {"name": "EOS-4.35.4M.swi"}},
                },
            },
            tag_query_results={
                "device:JPE00000001": [self.tag_element("JPE00000001")],
            },
        )

        selected = self.module.resolve_runtime_artifacts(
            ctx, "designed", "JPE00000001", ""
        )

        self.assertEqual(
            [artifact.filename for artifact in selected],
            ["EOS-4.34.6M.swi", "TerminAttr-1.40.10-1.swix"],
        )
        self.assertEqual(ctx.assignments_client.get_all_calls, 0)
        self.assertEqual(ctx.assignments_client.calls, 0)
        self.assertEqual(ctx.tag_client.requests, [])
        self.assertEqual(ctx.image_summary_client.calls, 0)

    def test_designed_device_list_run_transfers_full_studio_set_in_order(self):
        query = "device:JPE00000001 | device:JPE00000002"
        names = [
            "EOS-4.34.6M.swi",
            "TerminAttr-1.40.10-1.swix",
            "switchapp-1.15.1-1.10.swix",
        ]
        ctx = self.resource_ctx(
            {
                "DeviceID": "JPE00000001",
                "Source": "designed",
                "VRF": "MGMT",
                "Force": "False",
            },
            repository_config=self.designed_repository_config_records(),
            assignment_records=[],
            studio_inputs=[self.studio_software_inputs_record(query=query)],
            provisioned_device={"JPE00000001": self.provisioned_device()},
            tag_query_results={query: [self.tag_element("JPE00000001")]},
        )

        self.module.run(ctx)

        transfers = [
            command for command in ctx.commands
            if "curl " in command
            and ("/export/swi/swadapt" in command or "--output" in command)
        ]
        self.assertEqual(len(transfers), 3)
        for name, command in zip(names, transfers):
            self.assertIn(name, command)
        self.assertEqual(ctx.tag_client.requests, [])
        self.assertEqual(len(self.designed_resolution_logs(ctx)), 1)

    def test_designed_diagnostic_lists_committed_external_decisions(self):
        query = "device:JPE00000001"
        ctx = self.resource_ctx(
            {},
            repository_config=self.designed_repository_config_records(),
            assignment_records=[],
            studio_inputs=[self.studio_software_inputs_record(query=query)],
            tag_query_results={query: [self.tag_element("JPE00000001")]},
        )

        self.module.resolve_runtime_artifacts(ctx, "designed", "JPE00000001", "")

        self.assertEqual(
            self.designed_resolution_logs(ctx),
            [
                "Step: Designed resolution | Status: SUCCESS | "
                "Software Assignment: matched committed mainline assignment for "
                "JPE00000001; "
                "Image decision: EOS-4.34.6M.swi configured; "
                "include EOS-4.34.6M.swi; "
                "Streaming agent decision: external TerminAttr-1.40.10-1.swix "
                "configured; include TerminAttr-1.40.10-1.swix; "
                "Extensions decision: 1 configured; "
                "include switchapp-1.15.1-1.10.swix; "
                "Final: EOS-4.34.6M.swi (image), "
                "TerminAttr-1.40.10-1.swix (agent), "
                "switchapp-1.15.1-1.10.swix (extension)"
            ],
        )

    def test_designed_diagnostic_lists_committed_embedded_decisions(self):
        ctx = self.resource_ctx(
            {},
            repository_config=[self.repository_config_records()[0]],
            studio_inputs=[self.studio_software_inputs_record(
                agent="",
                extensions=(),
            )],
            assignments_available=False,
            tag_api_available=False,
        )

        self.module.resolve_runtime_artifacts(ctx, "designed", "JPE00000001", "")

        self.assertEqual(
            self.designed_resolution_logs(ctx),
            [
                "Step: Designed resolution | Status: SUCCESS | "
                "Software Assignment: matched committed mainline assignment for "
                "JPE00000001; "
                "Image decision: EOS-4.34.6M.swi configured; "
                "include EOS-4.34.6M.swi; "
                "Streaming agent decision: embedded configured; "
                "no separate streaming-agent artifact included; "
                "Extensions decision: 0 configured; "
                "no extension artifacts included; "
                "Final: EOS-4.34.6M.swi (image)"
            ],
        )

    def test_designed_does_not_fallback_to_assignments_when_studio_is_unavailable(self):
        ctx = self.resource_ctx(
            {},
            repository_config=self.designed_repository_config_records(),
            assignment_records=[
                self.assignment_record("switchapp-1.15.1-1.10.swix", "JPE00000001"),
                self.assignment_record("EOS-4.34.6M.swi", "JPE00000001"),
                self.assignment_record("TerminAttr-1.40.10-1.swix", "JPE00000001"),
            ],
        )

        with self.assertRaisesRegex(ValueError, "mainline root Inputs"):
            self.module.resolve_runtime_artifacts(
                ctx, "designed", "JPE00000001", ""
            )

        self.assertEqual(ctx.assignments_client.get_all_calls, 0)
        self.assertEqual(self.designed_resolution_logs(ctx), [])

    def test_designed_uppercase_swi_resolves_without_summary_fallback(self):
        names = ["EOS-4.34.6M.SWI", "switchapp-1.15.1-1.10.swix"]
        ctx = self.resource_ctx(
            {},
            repository_config=self.repository_artifact_records(names),
            assignment_records=[
                self.assignment_record(name, "JPE00000001")
                for name in names
            ],
            studio_inputs=[self.studio_software_inputs_record(
                image=names[0], agent="", extensions=(names[1],), path={}
            )],
        )

        selected = self.module.resolve_runtime_artifacts(
            ctx,
            "designed",
            "JPE00000001",
            "",
        )

        self.assertEqual([artifact.filename for artifact in selected], names)
        diagnostic = self.designed_resolution_logs(ctx)[0]
        self.assertIn("EOS-4.34.6M.SWI (image)", diagnostic)
        self.assertNotIn("Image summary ->", diagnostic)

    def test_designed_committed_assignment_run_transfers_full_set_in_order(self):
        names = [
            "EOS-4.34.6M.swi",
            "TerminAttr-1.40.10-1.swix",
            "switchapp-1.15.1-1.10.swix",
        ]
        ctx = self.resource_ctx(
            {
                "DeviceID": "JPE00000001",
                "Source": "designed",
                "Destination": "/mnt/flash/custom-image.swi",
                "VRF": "MGMT",
                "Force": "False",
            },
            repository_config=self.designed_repository_config_records(),
            provisioned_device={"JPE00000001": self.provisioned_device()},
            assignment_records=[
                self.assignment_record(name, "JPE00000001")
                for name in reversed(names)
            ],
            studio_inputs=[self.studio_software_inputs_record(path={})],
        )

        self.module.run(ctx)

        self.assertEqual(ctx.assignments_client.get_all_calls, 0)
        transfers = [
            command for command in ctx.commands
            if "curl " in command
            and ("/export/swi/swadapt" in command or "--output" in command)
        ]
        self.assertEqual(len(transfers), 3)
        for name, command in zip(names, transfers):
            self.assertIn(name, command)
        self.assertIn("/export/swi/swadapt /mnt/flash/custom-image.swi", transfers[0])
        self.assertIn("--output /mnt/flash/TerminAttr-1.40.10-1.swix", transfers[1])
        self.assertIn(
            "--output /mnt/flash/switchapp-1.15.1-1.10.swix",
            transfers[2],
        )
        self.assertEqual(len(self.designed_resolution_logs(ctx)), 1)

    def test_designed_ignores_get_one_assignments_and_unconfigured_artifact(self):
        assigned_names = [
            "EOS-4.34.6M.swi",
            "TerminAttr-1.40.10-1.swix",
            "switchapp-1.15.1-1.10.swix",
        ]
        extra = "unassigned-extension.rpm"
        ctx = self.resource_ctx(
            {
                "DeviceID": "JPE00000001",
                "Source": "designed",
                "VRF": "MGMT",
                "Force": "False",
            },
            repository_config=(
                self.designed_repository_config_records()
                + self.repository_artifact_records([extra])
            ),
            assignments={
                name: self.assignment_record(name, "JPE00000001")
                for name in assigned_names
            },
            provisioned_device={"JPE00000001": self.provisioned_device()},
            studio_inputs=[self.studio_software_inputs_record(path={})],
        )

        self.module.run(ctx)

        self.assertEqual(ctx.assignments_client.get_all_calls, 0)
        self.assertEqual(ctx.assignments_client.calls, 0)
        transfers = [
            command for command in ctx.commands
            if "curl " in command
            and ("/export/swi/swadapt" in command or "--output" in command)
        ]
        self.assertEqual(len(transfers), 3)
        for name, command in zip(assigned_names, transfers):
            self.assertIn(name, command)
        self.assertNotIn(extra, "\n".join(transfers))
        diagnostic = self.designed_resolution_logs(ctx)
        self.assertEqual(len(diagnostic), 1)
        self.assertIn("Software Assignment: matched committed mainline", diagnostic[0])

    def test_designed_embedded_run_skips_separate_agent(self):
        scenarios = (
            (
                "embedded",
                [
                    "EOS-4.34.6M.swi",
                    "switchapp-1.15.1-1.10.swix",
                ],
            ),
            ("image-only", ["EOS-4.34.6M.swi"]),
        )
        for label, names in scenarios:
            with self.subTest(label=label):
                ctx = self.resource_ctx(
                    {
                        "DeviceID": "JPE00000001",
                        "Source": "designed",
                        "VRF": "MGMT",
                        "Force": "False",
                    },
                    repository_config=self.designed_repository_config_records(),
                    provisioned_device={
                        "JPE00000001": self.provisioned_device(),
                    },
                    assignment_records=[
                        self.assignment_record(name, "JPE00000001")
                        for name in names
                    ],
                    studio_inputs=[self.studio_software_inputs_record(
                        agent="",
                        extensions=tuple(names[1:]),
                        path={},
                    )],
                )

                self.module.run(ctx)

                self.assertEqual(ctx.assignments_client.get_all_calls, 0)
                transfers = [
                    command for command in ctx.commands
                    if "curl " in command
                    and ("/export/swi/swadapt" in command or "--output" in command)
                ]
                self.assertEqual(len(transfers), len(names))
                self.assertNotIn("TerminAttr-1.40.10-1.swix", "\n".join(transfers))
                for name, command in zip(names, transfers):
                    self.assertIn(name, command)

    def test_designed_multi_extension_order_is_stable_across_resolutions(self):
        extension_a = "extension-a.swix"
        extension_b = "extension-b.swix"
        repository_config = (
            [self.repository_config_records()[0]]
            + [self.extension_repository_config_records()[0]]
            + self.repository_artifact_records([extension_b, extension_a])
        )
        assignment_names = [
            extension_a,
            "EOS-4.34.6M.swi",
            extension_b,
            "TerminAttr-1.40.10-1.swix",
        ]
        ctx = self.resource_ctx(
            {},
            repository_config=repository_config,
            assignment_records=[
                self.assignment_record(name, "JPE00000001")
                for name in assignment_names
            ],
            studio_inputs=[self.studio_software_inputs_record(
                extensions=(extension_b, extension_a), path={}
            )],
        )

        resolved = [
            [artifact.filename for artifact in self.module.resolve_runtime_artifacts(
                ctx,
                "designed",
                "JPE00000001",
                "",
            )]
            for _ in range(3)
        ]

        self.assertEqual(
            resolved,
            [
                [
                    "EOS-4.34.6M.swi",
                    "TerminAttr-1.40.10-1.swix",
                    extension_b,
                    extension_a,
                ]
            ] * 3,
        )

    def test_designed_committed_settings_ignore_partial_assignments(self):
        scenarios = {
            "missing agent": [
                "EOS-4.34.6M.swi",
                "switchapp-1.15.1-1.10.swix",
            ],
            "lone image": ["EOS-4.34.6M.swi"],
        }
        for label, assigned_names in scenarios.items():
            with self.subTest(label=label):
                ctx = self.resource_ctx(
                    {},
                    repository_config=self.designed_repository_config_records(),
                    assignment_records=[
                        self.assignment_record(name, "JPE00000001")
                        for name in assigned_names
                    ],
                    studio_inputs=[self.studio_software_inputs_record()],
                )

                selected = self.module.resolve_runtime_artifacts(
                    ctx,
                    "designed",
                    "JPE00000001",
                    "",
                )

                self.assertEqual(
                    [artifact.filename for artifact in selected],
                    [
                        "EOS-4.34.6M.swi",
                        "TerminAttr-1.40.10-1.swix",
                        "switchapp-1.15.1-1.10.swix",
                    ],
                )
                diagnostic = self.designed_resolution_logs(ctx)[0]
                self.assertIn(
                    "Software Assignment: matched committed mainline",
                    diagnostic,
                )
                self.assertEqual(ctx.assignments_client.get_all_calls, 0)

    def test_designed_committed_settings_ignore_extension_only_assignments(self):
        ctx = self.resource_ctx(
            {},
            repository_config=self.designed_repository_config_records(),
            assignment_records=[
                self.assignment_record("switchapp-1.15.1-1.10.swix", "JPE00000001"),
            ],
            studio_inputs=[self.studio_software_inputs_record()],
        )

        selected = self.module.resolve_runtime_artifacts(
            ctx,
            "designed",
            "JPE00000001",
            "",
        )

        self.assertEqual(
            [artifact.filename for artifact in selected],
            [
                "EOS-4.34.6M.swi",
                "TerminAttr-1.40.10-1.swix",
                "switchapp-1.15.1-1.10.swix",
            ],
        )
        diagnostic = self.designed_resolution_logs(ctx)[0]
        self.assertIn(
            "Extensions decision: 1 configured; include "
            "switchapp-1.15.1-1.10.swix",
            diagnostic,
        )
        self.assertEqual(ctx.assignments_client.get_all_calls, 0)

    def test_designed_assignment_errors_do_not_override_committed_settings(self):
        ctx = self.resource_ctx(
            {
                "DeviceID": "JPE00000001",
                "Source": "designed",
                "VRF": "MGMT",
                "Force": "False",
            },
            repository_config=self.designed_repository_config_records(),
            assignment_records=[
                self.assignment_record("missing-agent.swix", "JPE00000001"),
                self.assignment_record("missing-extension.rpm", "JPE00000001"),
            ],
            studio_inputs=[self.studio_software_inputs_record()],
            provisioned_device={"JPE00000001": self.provisioned_device()},
        )

        self.module.run(ctx)

        self.assertEqual(ctx.assignments_client.get_all_calls, 0)
        self.assertNotIn("missing-agent.swix", "\n".join(ctx.commands))
        self.assertNotIn("missing-extension.rpm", "\n".join(ctx.commands))
        self.assertEqual(len(self.designed_resolution_logs(ctx)), 1)
        self.assertTrue(ctx.transfer_ran)

    def test_designed_committed_image_overrides_conflicting_assignment_swi(self):
        ctx = self.resource_ctx(
            {},
            repository_config=(
                self.repository_config_records()[:2]
                + self.extension_repository_config_records()
            ),
            assignment_records=[
                self.assignment_record("EOS-4.34.6M.swi", "JPE00000001"),
            ],
            studio_inputs=[
                self.studio_software_inputs_record(image="EOS-4.35.4M.swi"),
            ],
        )

        selected = self.module.resolve_runtime_artifacts(
            ctx, "designed", "JPE00000001", ""
        )

        self.assertEqual(selected[0].filename, "EOS-4.35.4M.swi")
        self.assertNotIn(
            "EOS-4.34.6M.swi",
            [artifact.filename for artifact in selected],
        )
        self.assertEqual(ctx.assignments_client.get_all_calls, 0)
        self.assertEqual(len(self.designed_resolution_logs(ctx)), 1)

    def test_designed_missing_mainline_does_not_use_assignments(self):
        ctx = self.resource_ctx(
            {},
            repository_config=self.designed_repository_config_records(),
            assignment_records=[
                self.assignment_record("switchapp-1.15.1-1.10.swix", "JPE00000001"),
            ],
        )

        with self.assertRaises(ValueError) as raised:
            self.module.resolve_runtime_artifacts(
                ctx,
                "designed",
                "JPE00000001",
                "",
            )

        message = str(raised.exception)
        self.assertIn("committed mainline root Inputs record", message)
        self.assertEqual(ctx.assignments_client.get_all_calls, 0)
        self.assertEqual(self.designed_resolution_logs(ctx), [])

    def test_designed_image_summary_does_not_backfill_committed_decision(self):
        ctx = self.resource_ctx(
            {},
            repository_config=self.designed_repository_config_records(),
            assignment_records=[
                self.assignment_record("switchapp-1.15.1-1.10.swix", "JPE00000001"),
            ],
            studio_inputs=[
                self.studio_software_inputs_record(
                    image="TerminAttr-1.40.10-1.swix",
                    agent="",
                    extensions=(),
                ),
            ],
            image_summary={
                "JPE00000001": {
                    "value": {"b": {"name": "EOS-4.34.6M.swi"}},
                },
            },
        )

        selected = self.module.resolve_runtime_artifacts(
            ctx,
            "designed",
            "JPE00000001",
            "",
        )

        self.assertEqual(
            [artifact.filename for artifact in selected],
            ["TerminAttr-1.40.10-1.swix"],
        )
        diagnostic = self.designed_resolution_logs(ctx)[0]
        self.assertIn(
            "Image decision: TerminAttr-1.40.10-1.swix configured; "
            "include TerminAttr-1.40.10-1.swix",
            diagnostic,
        )
        self.assertNotIn("EOS-4.34.6M.swi", diagnostic)
        self.assertEqual(ctx.image_summary_client.calls, 0)
        self.assertEqual(len(self.designed_resolution_logs(ctx)), 1)

    def test_designed_resolution_diagnostic_reports_committed_decisions(self):
        ctx = self.resource_ctx(
            {},
            repository_config=self.designed_repository_config_records(),
            assignment_records=[
                self.assignment_record("EOS-4.34.6M.swi", "JPE00000001"),
                self.assignment_record("switchapp-1.15.1-1.10.swix", "JPE00000001"),
            ],
            studio_inputs=[self.studio_software_inputs_record()],
        )

        self.module.resolve_runtime_artifacts(ctx, "designed", "JPE00000001", "")

        self.assertEqual(
            self.designed_resolution_logs(ctx),
            [
                "Step: Designed resolution | Status: SUCCESS | "
                "Software Assignment: matched committed mainline assignment for "
                "JPE00000001; "
                "Image decision: EOS-4.34.6M.swi configured; "
                "include EOS-4.34.6M.swi; "
                "Streaming agent decision: external TerminAttr-1.40.10-1.swix "
                "configured; include TerminAttr-1.40.10-1.swix; "
                "Extensions decision: 1 configured; "
                "include switchapp-1.15.1-1.10.swix; "
                "Final: EOS-4.34.6M.swi (image), "
                "TerminAttr-1.40.10-1.swix (agent), "
                "switchapp-1.15.1-1.10.swix (extension)"
            ],
        )
        self.assert_structured_logs(ctx)

    def test_designed_source_uses_committed_assignment_and_cvp_device_ip(self):
        ctx = self.resource_ctx(
            {
                "DeviceID": "JPE00000001",
                "Source": "designed",
                "VRF": "MGMT",
                "Force": "False",
            },
            repository_config=self.repository_config_records(),
            provisioned_device={"JPE00000001": self.provisioned_device()},
            assignment_records=[
                self.assignment_record("EOS-4.34.6M.swi", "JPE00000002"),
                self.assignment_record("EOS-4.35.4M.swi", "JPE00000001"),
            ],
            studio_inputs=[self.studio_software_inputs_record(
                agent="", extensions=(), path={}
            )],
        )

        self.module.run(ctx)

        self.assert_structured_logs(ctx)
        transfer = "\n".join(ctx.commands)
        self.assertIn("/api/v1/files/software/repository-image/EOS-4.34.6M.swi", transfer)
        self.assertIn("--interface 192.0.2.221", transfer)
        self.assertIn("ns-MGMT", transfer)
        self.assertNotIn("/cvpservice/image/getImagebyId/", transfer)
        self.assertNotIn("secret-token", "\n".join(ctx.infos))
        self.assertEqual(ctx.http_paths, [])
        self.assertEqual(ctx.assignments_client.get_all_calls, 0)

    def test_designed_source_uses_studio_inputs_when_assignments_stub_is_missing(self):
        ctx = self.resource_ctx(
            {
                "DeviceID": "JPE00000001",
                "Source": "designed",
                "VRF": "MGMT",
                "Force": "False",
            },
            repository_config=self.repository_config_records(),
            provisioned_device={"JPE00000001": self.provisioned_device()},
            studio_inputs=[self.studio_software_inputs_record(
                agent="",
                extensions=(),
                query="device:JPE00000001 | device:JPE00000002",
                path={},
            )],
            assignments_available=False,
            tag_query_results={
                "device:JPE00000001 | device:JPE00000002": [
                    self.tag_element("JPE00000001"),
                ],
            },
        )

        self.module.run(ctx)

        transfer = "\n".join(ctx.commands)
        self.assertIn("/api/v1/files/software/repository-image/EOS-4.34.6M.swi", transfer)
        self.assertEqual(ctx.http_paths, [])
        self.assertEqual(ctx.tag_client.requests, [])

    def test_designed_source_preloads_studio_streaming_agent_and_extensions(self):
        ctx = self.resource_ctx(
            {
                "DeviceID": "JPE00000001",
                "Source": "designed",
                "VRF": "MGMT",
                "Force": "False",
            },
            repository_config=(
                [self.repository_config_records()[0]]
                + self.extension_repository_config_records()
            ),
            provisioned_device={"JPE00000001": self.provisioned_device()},
            studio_inputs=[self.studio_software_inputs_record(path={})],
            assignments_available=False,
        )

        self.module.run(ctx)

        transfer = "\n".join(ctx.commands)
        self.assertIn("/api/v1/files/software/repository-image/EOS-4.34.6M.swi", transfer)
        self.assertIn("/api/v1/files/software/repository-agent/TerminAttr-1.40.10-1.swix", transfer)
        self.assertIn(
            "/api/v1/files/software/repository-extension/switchapp-1.15.1-1.10.swix",
            transfer,
        )
        self.assertIn("/export/swi/swadapt /mnt/flash/EOS-4.34.6M.swi", transfer)
        self.assertIn("--output /mnt/flash/TerminAttr-1.40.10-1.swix", transfer)
        self.assertIn("--output /mnt/flash/switchapp-1.15.1-1.10.swix", transfer)

    def test_designed_source_fails_when_extensions_field_is_missing(self):
        ctx = self.resource_ctx(
            {
                "DeviceID": "JPE00000001",
                "Source": "designed",
                "VRF": "MGMT",
                "Force": "False",
            },
            repository_config=[self.repository_config_records()[0]],
            provisioned_device={"JPE00000001": self.provisioned_device()},
            studio_inputs=[
                {
                    "value": {
                        "key": {
                            "studioId": "studio-software-management",
                            "workspaceId": "",
                        },
                        "inputs": json.dumps({
                            "softwareResolver": [
                                {
                                    "inputs": {
                                        "softwareGroup": {
                                            "imageName": "EOS-4.34.6M.swi",
                                            "streamingAgentName": (
                                                "TerminAttr-1.40.10-1.swix"
                                            ),
                                        },
                                    },
                                    "tags": {"query": "device:JPE00000001"},
                                }
                            ]
                        }),
                    }
                }
            ],
            assignment_records=[
                self.assignment_record("EOS-4.34.6M.swi", "JPE00000001"),
            ],
        )

        with self.assertRaisesRegex(ValueError, "extensionsCollection"):
            self.module.run(ctx)

        self.assertEqual(ctx.assignments_client.get_all_calls, 0)
        self.assertEqual(self.designed_resolution_logs(ctx), [])

    def test_running_source_uses_inventory_software_version(self):
        ctx = self.resource_ctx(
            {
                "DeviceID": "JPE00000001",
                "Source": "running",
                "VRF": "MGMT",
                "Force": "False",
            },
            repository_config=[self.repository_config_records()[0]],
            provisioned_device={"JPE00000001": self.provisioned_device()},
            inventory_device={"JPE00000001": self.inventory_device()},
        )

        self.module.run(ctx)

        self.assertIn("EOS-4.34.6M.swi", "\n".join(ctx.commands))
        self.assertEqual(ctx.http_paths, [])

    def test_running_source_falls_back_to_inventory_when_summary_does_not_match(self):
        ctx = self.resource_ctx(
            {
                "DeviceID": "JPE00000001",
                "Source": "running",
                "VRF": "MGMT",
                "Force": "False",
            },
            repository_config=[self.repository_config_records()[0]],
            provisioned_device={"JPE00000001": self.provisioned_device()},
            image_summary={
                "JPE00000001": {"value": {"a": {"name": "EOS-4.99.0F.swi"}}}
            },
            inventory_device={"JPE00000001": self.inventory_device()},
        )

        self.module.run(ctx)

        self.assertIn("EOS-4.34.6M.swi", "\n".join(ctx.commands))
        self.assertEqual(ctx.http_paths, [])

    def test_auto_vrf_falls_back_to_mgmt_when_detection_is_empty(self):
        ctx = self.resource_ctx(
            {
                "DeviceID": "JPE00000001",
                "Source": "repository",
                "Repository Image": "4.34.6M",
                "Force": "False",
            },
            repository_config=[self.repository_config_records()[0]],
            provisioned_device={"JPE00000001": self.provisioned_device()},
        )

        self.module.run(ctx)

        self.assertIn("ns-MGMT", "\n".join(ctx.commands))
        self.assertEqual(ctx.http_paths, [])


if __name__ == "__main__":
    unittest.main()
