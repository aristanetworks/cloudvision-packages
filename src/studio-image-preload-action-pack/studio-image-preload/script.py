# Copyright (c) 2026 Arista Networks, Inc.
# Use of this source code is governed by the Apache License 2.0
# that can be found in the COPYING file.

import json
import re
from dataclasses import dataclass
from importlib import import_module
from posixpath import basename, dirname
from shlex import quote as shell_quote
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import quote as url_quote
from urllib.parse import urlparse


LEGACY_IMAGE_ENDPOINT = "/cvpservice/image/getImagebyId/"
FILE_API_PREFIX = "/api/v1/files/"
ACCESS_TOKEN_PATTERN = re.compile(r"(access_token=)[^\"'\s]+")
DEFAULT_SOURCE = "designed"
DEFAULT_VRF = "MGMT"
DEFAULT_TIMEOUT = 3597
DEFAULT_SPEED_TIME = 120
DEFAULT_SPEED_LIMIT = 102400
RESOURCE_API_TIMEOUT = 60
FLASH_ROOT = "/mnt/flash"
AUTO_VALUES = ("", "auto", "<auto>")
LOG_STATUS_STARTED = "STARTED"
LOG_STATUS_SUCCESS = "SUCCESS"
LOG_STATUS_WARNING = "WARNING"
LOG_STATUS_ERROR = "ERROR"
LOG_STATUS_SKIPPED = "SKIPPED"
LOG_STATUSES = frozenset((
    LOG_STATUS_STARTED,
    LOG_STATUS_SUCCESS,
    LOG_STATUS_WARNING,
    LOG_STATUS_ERROR,
    LOG_STATUS_SKIPPED,
))

PATH_FIELDS = (
    "fileServerPath",
    "file_server_path",
    "fileServerUri",
    "file_server_uri",
    "filePath",
    "file_path",
    "storagePath",
    "storage_path",
    "path",
    "uri",
    "url",
)
NAME_FIELDS = (
    "name",
    "image",
    "imageName",
    "image_name",
    "filename",
    "fileName",
    "file_name",
    "softwareImage",
    "software_image",
)
RUNNING_FIELDS = (
    "softwareVersion",
    "runningVersion",
    "running_version",
    "runningImage",
    "running_image",
    "bootedImage",
    "booted_image",
    "softwareImage",
    "software_image",
)
VERSION_FIELDS = (
    "version",
    "softwareVersion",
    "releaseVersion",
    "imageVersion",
    "image_version",
)
SIZE_FIELDS = (
    "size",
    "sizeBytes",
    "size_bytes",
    "fileSize",
    "file_size",
    "bytes",
)
SHA512_FIELDS = ("sha512", "sha512sum", "sha512Sum", "sha512Checksum", "digest")
MD5_FIELDS = ("md5", "md5sum", "md5Sum", "md5Checksum")
IP_FIELDS = (
    "ipAddress",
    "ip_address",
    "ipv4Address",
    "ipv4_address",
    "managementIp",
    "management_ip",
    "managementIpAddress",
    "management_ip_address",
)
INTERNAL_AUTHORITY_FRAGMENTS = (
    ".svc.cluster.local",
    "ambassador.default.svc",
)
API_SERVER_PORTS = ("9900",)
STUDIO_SOFTWARE_MANAGEMENT_ID = "studio-software-management"


@dataclass
class Artifact:
    name: str
    filename: str
    file_server_path: str
    version: str = ""
    size: Optional[int] = None
    sha512: str = ""
    md5: str = ""


@dataclass
class DownloadPlan:
    action: str
    reason: str


@dataclass(frozen=True)
class DesignedSoftwareDecision:
    image_selector: str
    agent_mode: str
    agent_selector: str
    extension_selectors: Tuple[str, ...]


def iter_dicts(value: Any) -> Iterable[Dict[str, Any]]:
    if isinstance(value, dict):
        yield value
        for nested in value.values():
            yield from iter_dicts(nested)
    elif isinstance(value, list):
        for item in value:
            yield from iter_dicts(item)


def unwrap_resource(record: Any) -> Any:
    value = record
    while isinstance(value, dict):
        if "result" in value and isinstance(value["result"], dict):
            value = value["result"]
            continue
        if "value" in value and isinstance(value["value"], dict):
            value = value["value"]
            continue
        break
    return value


def string_value(value: Any) -> str:
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, dict):
        nested = value.get("value")
        if isinstance(nested, str):
            return nested.strip()
    return ""


def first_string(record: Any, field_names: Iterable[str]) -> str:
    names = set(field_names)
    for item in iter_dicts(unwrap_resource(record)):
        key = item.get("key")
        if isinstance(key, dict) and "name" in names:
            value = string_value(key.get("name"))
            if value:
                return value
        for field in field_names:
            value = string_value(item.get(field))
            if value:
                return value
    return ""


def first_int(record: Any, field_names: Iterable[str]) -> Optional[int]:
    for item in iter_dicts(unwrap_resource(record)):
        for field in field_names:
            value = item.get(field)
            if isinstance(value, int):
                return value
            if isinstance(value, str) and value.strip().isdigit():
                return int(value.strip())
            if isinstance(value, dict):
                nested = value.get("value")
                if isinstance(nested, int):
                    return nested
                if isinstance(nested, str) and nested.strip().isdigit():
                    return int(nested.strip())
    return None


def records_from_payload(payload: Any) -> List[Any]:
    if isinstance(payload, list):
        return payload
    if payload in ({}, None):
        return []
    return [payload]


def message_to_dict(message: Any) -> Any:
    if isinstance(message, (dict, list, str, int, bool)) or message is None:
        return message
    try:
        from google.protobuf.json_format import MessageToDict
        return MessageToDict(message, preserving_proto_field_name=True)
    except Exception:
        return message


def resource_response_value(response: Any) -> Any:
    if isinstance(response, dict):
        return unwrap_resource(response)
    value = getattr(response, "value", response)
    return message_to_dict(value)


def wrapped_string(value: str) -> Any:
    try:
        from google.protobuf import wrappers_pb2 as wrappers
        return wrappers.StringValue(value=value)
    except Exception:
        return {"value": value}


def first_response_text(command_responses: Any) -> str:
    for item in iter_dicts(command_responses):
        response = item.get("response")
        if isinstance(response, str) and response.strip():
            return response.strip()
        if isinstance(response, dict):
            text = "\n".join(str(value) for value in response.values() if value)
            if text.strip():
                return text.strip()
    return ""


def normalize_authority(authority: str, strip_ports: Iterable[str] = ()) -> str:
    cleaned = authority.strip()
    if not cleaned:
        raise ValueError("CloudVision authority could not be determined")
    parsed = urlparse(cleaned if "://" in cleaned else f"//{cleaned}")
    host = parsed.hostname or ""
    try:
        port = parsed.port
    except ValueError:
        port = None
    if not host:
        raise ValueError("CloudVision authority could not be determined")
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    if port and str(port) not in set(strip_ports):
        return f"{host}:{port}"
    return host.rstrip("/")


def is_internal_authority(authority: str) -> bool:
    normalized = normalize_authority(authority).casefold().rstrip(".")
    return any(fragment in normalized for fragment in INTERNAL_AUTHORITY_FRAGMENTS)


def normalize_file_server_path(file_server_path: str) -> str:
    path = file_server_path.strip()
    if LEGACY_IMAGE_ENDPOINT in path:
        raise ValueError("legacy image endpoint is not supported")
    parsed = urlparse(path)
    if parsed.scheme:
        path = parsed.path
    if FILE_API_PREFIX in path:
        path = path.split(FILE_API_PREFIX, 1)[1]
    path = path.lstrip("/")
    if not path.startswith("software/"):
        raise ValueError("Software Management file path must start with software/")
    parts = path.split("/")
    if len(parts) < 3 or not all(parts[:3]):
        raise ValueError("Software Management file path is incomplete")
    return path


def build_file_api_url(authority: str, file_server_path: str) -> str:
    normalized = normalize_file_server_path(file_server_path)
    encoded = "/".join(url_quote(part, safe="") for part in normalized.split("/"))
    return f"https://{normalize_authority(authority)}/api/v1/files/{encoded}"


def parse_version_from_filename(filename: str) -> str:
    stem = basename(filename)
    for prefix in ("EOS64-", "EOSarm-", "EOS-"):
        if stem.startswith(prefix) and stem.casefold().endswith(".swi"):
            return stem[len(prefix):-4]
    return ""


def extract_artifact(record: Any) -> Optional[Artifact]:
    for item in iter_dicts(unwrap_resource(record)):
        for field in PATH_FIELDS:
            path = string_value(item.get(field))
            if not path:
                continue
            try:
                file_server_path = normalize_file_server_path(path)
            except ValueError:
                continue
            filename = first_string(record, ("filename", "fileName", "file_name"))
            filename = filename or basename(file_server_path)
            name = first_string(record, NAME_FIELDS) or filename
            version = first_string(record, VERSION_FIELDS) or parse_version_from_filename(filename)
            return Artifact(
                name=name,
                filename=filename,
                file_server_path=file_server_path,
                version=version,
                size=first_int(record, SIZE_FIELDS),
                sha512=first_string(record, SHA512_FIELDS),
                md5=first_string(record, MD5_FIELDS),
            )
    return None


def artifacts_from_repository(repository: Any) -> List[Artifact]:
    artifacts = []
    seen = set()
    for record in records_from_payload(repository):
        artifact = extract_artifact(record)
        if artifact and artifact.filename not in seen:
            seen.add(artifact.filename)
            artifacts.append(artifact)
    return artifacts


def pure_device_query_ids(query: str) -> Optional[List[str]]:
    terms = re.split(r"\s*(?:\||\bOR\b)\s*", query, flags=re.IGNORECASE)
    device_ids = []
    for term in terms:
        match = re.fullmatch(r"device:\s*(.+)", term)
        if not match:
            return None
        values = [value.strip() for value in match.group(1).split(",")]
        if not values or any(
            not re.fullmatch(r"[A-Za-z0-9_.-]+", value)
            for value in values
        ):
            return None
        device_ids.extend(values)
    return device_ids


def optional_string_value(value: Any) -> Optional[str]:
    if isinstance(value, str):
        return value
    if isinstance(value, dict) and isinstance(value.get("value"), str):
        return value["value"]
    return None


def committed_mainline_inputs_record(record: Any) -> bool:
    value = unwrap_resource(record)
    if not isinstance(value, dict):
        return False
    key = value.get("key")
    if not isinstance(key, dict):
        return False

    studio_id = optional_string_value(
        key["studioId"] if "studioId" in key else key.get("studio_id")
    )
    if studio_id != STUDIO_SOFTWARE_MANAGEMENT_ID:
        return False

    if "workspaceId" in key:
        workspace_id = optional_string_value(key["workspaceId"])
    elif "workspace_id" in key:
        workspace_id = optional_string_value(key["workspace_id"])
    else:
        return False
    if workspace_id != "":
        return False

    if "path" not in key or key["path"] == {}:
        return True
    path = key["path"]
    if not isinstance(path, dict):
        return False
    if "values" not in path:
        return True
    return isinstance(path["values"], list) and not path["values"]


def committed_mainline_record(records: Any, source: str) -> Optional[Any]:
    matches = [
        record for record in records_from_payload(records)
        if committed_mainline_inputs_record(record)
    ]
    if not matches:
        return None
    if len(matches) == 1:
        return matches[0]

    fragments = []
    for record in matches:
        value = unwrap_resource(record)
        inputs = value.get("inputs") if isinstance(value, dict) else None
        if not isinstance(inputs, str):
            raise ValueError(
                f"Multiple Software Management committed mainline root records "
                f"returned by {source}"
            )
        try:
            parsed = json.loads(inputs)
        except Exception:
            pass
        else:
            if isinstance(parsed, dict):
                raise ValueError(
                    "Multiple Software Management committed mainline root "
                    f"records returned by {source}"
                )
        fragments.append(inputs)

    combined = "".join(fragments)
    try:
        parsed = json.loads(combined)
    except Exception as err:
        detail = sanitize_log_text(f"{type(err).__name__}: {err}")
        raise ValueError(
            f"Malformed fragmented Software Management committed mainline "
            f"Inputs from {source}: {detail}"
        ) from None
    if not isinstance(parsed, dict):
        raise ValueError(
            f"Malformed fragmented Software Management committed mainline "
            f"Inputs from {source}: fragments did not form one JSON object"
        )

    synthetic = dict(unwrap_resource(matches[0]))
    synthetic["inputs"] = combined
    return synthetic


def load_committed_software_inputs(ctx: Any) -> Any:
    state_error = ""
    try:
        state_records = cv_resource_get_all(
            ctx,
            "arista.studio.v1.services",
            "InputsServiceStub",
            "InputsStreamRequest",
        )
    except Exception as err:
        state_error = sanitize_log_text(f"{type(err).__name__}: {err}")
    else:
        state_record = committed_mainline_record(state_records, "Studio Inputs state")
        if state_record is not None:
            return state_record

    config_error = ""
    try:
        config_records = cv_resource_get_all(
            ctx,
            "arista.studio.v1.services",
            "InputsConfigServiceStub",
            "InputsConfigStreamRequest",
        )
    except Exception as err:
        config_error = sanitize_log_text(f"{type(err).__name__}: {err}")
    else:
        config_record = committed_mainline_record(
            config_records, "Studio InputsConfig"
        )
        if config_record is not None:
            return config_record

    details = []
    if state_error:
        details.append(f"Inputs state unavailable: {state_error}")
    if config_error:
        details.append(f"InputsConfig unavailable: {config_error}")
    suffix = f" ({'; '.join(details)})" if details else ""
    raise ValueError(
        "Software Management committed mainline root Inputs record was not found"
        + suffix
    )


def strict_studio_inputs_payload(record: Any) -> Dict[str, Any]:
    value = unwrap_resource(record)
    if not isinstance(value, dict):
        raise ValueError("Software Management committed mainline Inputs is malformed")
    inputs = value.get("inputs")
    if isinstance(inputs, str):
        try:
            inputs = json.loads(inputs)
        except Exception:
            raise ValueError(
                "Software Management committed mainline Inputs JSON is malformed"
            ) from None
    if not isinstance(inputs, dict):
        raise ValueError("Software Management committed mainline Inputs is malformed")
    return inputs


def strict_software_group_decision(resolver: Dict[str, Any], index: int
                                   ) -> DesignedSoftwareDecision:
    resolver_inputs = resolver.get("inputs")
    if not isinstance(resolver_inputs, dict):
        raise ValueError(f"Software Assignment {index} inputs are malformed")
    software_group = resolver_inputs.get("softwareGroup")
    if not isinstance(software_group, dict):
        raise ValueError(f"Software Assignment {index} softwareGroup is malformed")

    image = software_group.get("imageName")
    if not isinstance(image, str) or not image.strip():
        raise ValueError(
            "Software Settings imageName must be a non-empty string"
        )
    image = image.strip()

    if "streamingAgentName" not in software_group:
        raise ValueError("Software Settings streamingAgentName key is required")
    agent = software_group["streamingAgentName"]
    if agent is None:
        agent_mode = "embedded"
        agent_selector = ""
    elif isinstance(agent, str):
        agent_selector = agent.strip()
        agent_mode = "external" if agent_selector else "embedded"
    else:
        raise ValueError(
            "Software Settings streamingAgentName must be null or a string"
        )

    if "extensionsCollection" not in software_group:
        raise ValueError("Software Settings extensionsCollection key is required")
    extensions = software_group["extensionsCollection"]
    if not isinstance(extensions, list):
        raise ValueError("Software Settings extensionsCollection must be a list")
    extension_selectors = []
    seen_extensions = set()
    for extension_index, extension in enumerate(extensions):
        if not isinstance(extension, dict):
            raise ValueError(
                f"Software Settings extensionName at index {extension_index} "
                "must be a non-empty string"
            )
        extension_name = extension.get("extensionName")
        if not isinstance(extension_name, str) or not extension_name.strip():
            raise ValueError(
                f"Software Settings extensionName at index {extension_index} "
                "must be a non-empty string"
            )
        extension_name = extension_name.strip()
        if extension_name in seen_extensions:
            raise ValueError(
                f"Software Settings contains duplicate extension selector "
                f"'{sanitize_log_text(extension_name)}'"
            )
        seen_extensions.add(extension_name)
        extension_selectors.append(extension_name)

    return DesignedSoftwareDecision(
        image_selector=image,
        agent_mode=agent_mode,
        agent_selector=agent_selector,
        extension_selectors=tuple(extension_selectors),
    )


def load_designed_software_decision(ctx: Any,
                                    device_id: str) -> DesignedSoftwareDecision:
    record = load_committed_software_inputs(ctx)
    inputs = strict_studio_inputs_payload(record)
    resolvers = inputs.get("softwareResolver")
    if not isinstance(resolvers, list):
        raise ValueError("Software Assignment list is missing or malformed")

    matches = []
    for index, resolver in enumerate(resolvers):
        if not isinstance(resolver, dict):
            raise ValueError(f"Software Assignment {index} is malformed")
        tags = resolver.get("tags")
        query = tags.get("query") if isinstance(tags, dict) else None
        if not isinstance(query, str) or not query.strip():
            raise ValueError(
                f"Software Assignment {index} has an unsupported device selector"
            )
        query = query.strip()
        device_ids = pure_device_query_ids(query)
        if device_ids is None:
            raise ValueError(
                f"Software Assignment {index} has unsupported device selector "
                f"'{sanitize_log_text(query)}'"
            )
        if device_id in device_ids:
            matches.append((resolver, index))

    if not matches:
        raise ValueError(
            f"No matching committed Software Assignment for device {device_id}"
        )
    if len(matches) > 1:
        raise ValueError(
            f"Multiple committed Software Assignments match device {device_id}"
        )
    return strict_software_group_decision(*matches[0])


def running_identifier(running: Any) -> str:
    artifact = extract_artifact(running)
    if artifact:
        return artifact.filename
    return first_string(running, RUNNING_FIELDS)


def image_identifier_from_summary(summary: Any, side: str) -> str:
    for item in iter_dicts(unwrap_resource(summary)):
        image = item.get(side)
        if not isinstance(image, dict):
            continue
        name = first_string(image, ("name", "imageName", "filename", "fileName"))
        if name:
            return name
        version = first_string(image, VERSION_FIELDS)
        if version:
            return version
    return ""


def artifact_matches(artifact: Artifact, selector: str) -> bool:
    wanted = selector.strip().casefold()
    if not wanted:
        return False
    candidates = {
        artifact.name.casefold(),
        artifact.filename.casefold(),
        artifact.version.casefold(),
        parse_version_from_filename(artifact.filename).casefold(),
    }
    if wanted in candidates:
        return True
    return wanted in artifact.filename.casefold()


def find_artifact(artifacts: List[Artifact], selector: str) -> Artifact:
    matches = [artifact for artifact in artifacts if artifact_matches(artifact, selector)]
    if not matches:
        raise ValueError(f"No Software Management artifact matched '{selector}'")
    if len(matches) > 1:
        exact = [
            artifact for artifact in matches
            if selector.casefold() in {artifact.name.casefold(), artifact.filename.casefold()}
        ]
        if len(exact) == 1:
            return exact[0]
        names = ", ".join(artifact.filename for artifact in matches)
        raise ValueError(
            f"selector '{selector}' matched {len(matches)} artifacts: {names}"
        )
    return matches[0]


def unique_artifacts(artifacts: Iterable[Artifact]) -> List[Artifact]:
    selected = []
    seen = set()
    for artifact in artifacts:
        key = artifact.file_server_path.casefold()
        if key not in seen:
            seen.add(key)
            selected.append(artifact)
    return selected


def resolve_designed_software_artifacts(
        artifacts: List[Artifact], decision: DesignedSoftwareDecision) -> List[Artifact]:
    configured = [("imageName", decision.image_selector)]
    if decision.agent_mode == "external":
        configured.append(("streamingAgentName", decision.agent_selector))
    configured.extend(
        ("extensionName", selector)
        for selector in decision.extension_selectors
    )

    resolved = []
    for field, selector in configured:
        try:
            resolved.append(find_artifact(artifacts, selector))
        except Exception as err:
            raise ValueError(
                f"Software Settings {field} '{sanitize_log_text(selector)}' "
                f"could not be resolved: "
                f"{sanitize_log_text(f'{type(err).__name__}: {err}')}"
            ) from None
    return resolved


def parse_csv_list(value: str) -> List[str]:
    selected = []
    seen = set()
    for token in (value or "").split(","):
        cleaned = token.strip()
        key = cleaned.casefold()
        if cleaned and key not in seen:
            seen.add(key)
            selected.append(cleaned)
    return selected


def find_repository_selector(artifacts: List[Artifact], token: str, field: str) -> Artifact:
    # Repository selection is not a hot path. Keep this diagnostic precompute
    # alongside find_artifact so the reported match count remains explicit
    # without introducing a second matching implementation.
    matches = [artifact for artifact in artifacts if artifact_matches(artifact, token)]
    try:
        return find_artifact(artifacts, token)
    except ValueError:
        count = len(matches)
        detail = f"{field} token '{token}': matched {count} artifacts in repository"
        if count > 1:
            detail += "; be more specific"
        raise ValueError(detail) from None


def running_artifact_from_summary(ctx: Any, device_id: str,
                                  artifacts: List[Artifact]) -> Optional[Artifact]:
    try:
        summary = load_image_summary(ctx, device_id)
    except Exception:
        return None
    selector = image_identifier_from_summary(summary, "a")
    if selector:
        try:
            return find_artifact(artifacts, selector)
        except Exception:
            return None
    return None


def resolve_runtime_artifacts(ctx: Any, source: str, device_id: str,
                              repository_image: str, repository_agent: str = "",
                              repository_extensions: str = "") -> List[Artifact]:
    repository = load_repository(ctx)
    artifacts = artifacts_from_repository(repository)
    mode = (source or DEFAULT_SOURCE).strip().casefold()

    if mode == "designed":
        decision = load_designed_software_decision(ctx, device_id)
        designed = resolve_designed_software_artifacts(artifacts, decision)
        log_committed_designed_resolution(
            ctx, device_id, decision, designed
        )
        return designed

    if mode == "running":
        artifact = running_artifact_from_summary(ctx, device_id, artifacts)
        if artifact:
            return [artifact]
        running = load_running(ctx, device_id)
        selector = running_identifier(running)
        if not selector:
            raise ValueError(f"No running EOS image found for {device_id}")
        return [find_artifact(artifacts, selector)]

    if mode in ("repository", "explicit"):
        repository_image = auto_arg(repository_image)
        if not repository_image:
            raise ValueError("Repository source requires a repository image name or version")
        selected = [find_repository_selector(
            artifacts, repository_image, "Repository Image"
        )]
        agent = auto_arg(repository_agent)
        if agent:
            selected.append(find_repository_selector(
                artifacts, agent, "Repository Streaming Agent"
            ))
        extensions = parse_csv_list(auto_arg(repository_extensions))
        selected.extend(
            find_repository_selector(artifacts, token, "Repository Extensions")
            for token in extensions
        )
        return unique_artifacts(selected)

    raise ValueError("source must be one of designed, running, or repository")


def default_destination(filename: str) -> str:
    return f"{FLASH_ROOT}/{basename(filename)}"


def destination_for_artifact(artifact: Artifact, destination_override: str, index: int) -> str:
    destination = destination_override.strip()
    if not destination:
        return default_destination(artifact.filename)
    if destination.endswith("/"):
        return f"{destination.rstrip('/')}/{basename(artifact.filename)}"
    # Index 0 is the SWI by designed sorting or repository construction order.
    if index == 0:
        return destination
    return default_destination(artifact.filename)


def render_curl_command(url: str, vrf: str, source_ip: str, token: str,
                        redacted: bool = False,
                        speed_time: int = DEFAULT_SPEED_TIME,
                        speed_limit: int = DEFAULT_SPEED_LIMIT,
                        output: str = "") -> str:
    cookie_value = "<redacted>" if redacted else token
    netns_parts = ()
    if vrf.strip().casefold() != "default":
        netns = vrf if vrf.startswith("ns-") else f"ns-{vrf}"
        netns_parts = ("sudo", "ip", "netns", "exec", shell_quote(netns))
    curl_parts = netns_parts + (
        "curl",
        shell_quote(url),
        "--insecure",
        "--cookie",
        shell_quote(f"access_token={cookie_value}"),
        "--fail",
        "--speed-time",
        str(speed_time),
        "--speed-limit",
        str(speed_limit),
        "-sS",
        "--interface",
        shell_quote(source_ip),
    )
    if output:
        curl_parts = curl_parts + ("--output", shell_quote(output))
    return " ".join(curl_parts)


def render_timed_bash_pipeline(payload: str, timeout: int = DEFAULT_TIMEOUT) -> str:
    return " ".join((
        "bash",
        "timeout",
        str(timeout),
        "bash",
        "-o",
        "pipefail",
        "-c",
        shell_quote(payload),
    ))


def render_preload_command(url: str, destination: str, vrf: str, source_ip: str,
                           token: str, redacted: bool = False,
                           timeout: int = DEFAULT_TIMEOUT,
                           speed_time: int = DEFAULT_SPEED_TIME,
                           speed_limit: int = DEFAULT_SPEED_LIMIT) -> str:
    curl_command = render_curl_command(
        url,
        vrf,
        source_ip,
        token,
        redacted=redacted,
        speed_time=speed_time,
        speed_limit=speed_limit,
    )
    pipeline = f"{curl_command} | /export/swi/swadapt {shell_quote(destination)}"
    return render_timed_bash_pipeline(pipeline, timeout)


def render_file_preload_command(url: str, destination: str, vrf: str, source_ip: str,
                                token: str, redacted: bool = False,
                                timeout: int = DEFAULT_TIMEOUT,
                                speed_time: int = DEFAULT_SPEED_TIME,
                                speed_limit: int = DEFAULT_SPEED_LIMIT) -> str:
    curl_command = render_curl_command(
        url,
        vrf,
        source_ip,
        token,
        redacted=redacted,
        speed_time=speed_time,
        speed_limit=speed_limit,
        output=destination,
    )
    return render_timed_bash_pipeline(curl_command, timeout)


def render_artifact_preload_command(artifact: Artifact, url: str, destination: str,
                                    vrf: str, source_ip: str, token: str,
                                    redacted: bool = False) -> str:
    if is_swi_artifact(artifact):
        return render_preload_command(url, destination, vrf, source_ip, token, redacted)
    return render_file_preload_command(url, destination, vrf, source_ip, token, redacted)


def render_bash_command(script: str, timeout: int = 120) -> str:
    return f"bash timeout {timeout} bash -c {shell_quote(script)}"


def plan_download(existing_size: Optional[int], target_verified: bool,
                  force: bool) -> DownloadPlan:
    if force:
        return DownloadPlan("rewrite", "force requested")
    if existing_size is None:
        return DownloadPlan("download", "target file is absent")
    if target_verified:
        return DownloadPlan("skip", "target file already verifies")
    return DownloadPlan("rewrite", "target file exists but verification failed")


def parse_existing_size(command_responses: Any) -> Optional[int]:
    for item in iter_dicts(command_responses):
        response = item.get("response")
        if isinstance(response, str):
            text = response
        elif isinstance(response, dict):
            text = "\n".join(str(value) for value in response.values())
        else:
            continue
        for token in text.split():
            if token.isdigit():
                return int(token)
    return None


def normalize_checksum(value: str) -> str:
    checksum = value.strip().casefold()
    if ":" in checksum:
        checksum = checksum.rsplit(":", 1)[1].strip()
    return checksum


def expected_checksum(artifact: Artifact) -> Tuple[str, str]:
    if artifact.sha512:
        return "sha512", normalize_checksum(artifact.sha512)
    if artifact.md5:
        return "md5", normalize_checksum(artifact.md5)
    return "md5", ""


def parse_checksum(command_responses: Any) -> str:
    text = first_response_text(command_responses)
    for token in text.split():
        if token.strip():
            return normalize_checksum(token)
    return ""


def is_swi_artifact(artifact: Artifact) -> bool:
    return artifact.filename.casefold().endswith(".swi")


def is_eos_verifiable_artifact(artifact: Artifact) -> bool:
    return artifact.filename.casefold().endswith((".swi", ".swix"))


def artifact_filenames(artifacts: Iterable[Artifact]) -> str:
    return ", ".join(artifact.filename for artifact in artifacts)


def log_committed_designed_resolution(
        ctx: Any, device_id: str, decision: DesignedSoftwareDecision,
        artifacts: List[Artifact]) -> None:
    image = artifacts[0]
    next_index = 1
    details = [
        f"Software Assignment: matched committed mainline assignment for {device_id}",
        f"Image decision: {image.filename} configured; include {image.filename}",
    ]
    final_parts = [f"{image.filename} (image)"]

    if decision.agent_mode == "external":
        agent = artifacts[next_index]
        next_index += 1
        details.append(
            f"Streaming agent decision: external {agent.filename} configured; "
            f"include {agent.filename}"
        )
        final_parts.append(f"{agent.filename} (agent)")
    else:
        details.append(
            "Streaming agent decision: embedded configured; "
            "no separate streaming-agent artifact included"
        )

    extensions = artifacts[next_index:]
    if extensions:
        extension_names = artifact_filenames(extensions)
        details.append(
            f"Extensions decision: {len(extensions)} configured; "
            f"include {extension_names}"
        )
        final_parts.extend(
            f"{extension.filename} (extension)" for extension in extensions
        )
    else:
        details.append(
            "Extensions decision: 0 configured; no extension artifacts included"
        )
    details.append(f"Final: {', '.join(final_parts)}")
    log_step(
        ctx,
        "Designed resolution",
        LOG_STATUS_SUCCESS,
        "; ".join(details),
    )


def flash_verify_path(destination: str) -> str:
    destination = destination.strip()
    if destination.startswith("flash:"):
        return destination
    flash_prefix = f"{FLASH_ROOT.rstrip('/')}/"
    if destination.startswith(flash_prefix):
        return f"flash:{destination[len(flash_prefix):].lstrip('/')}"
    return destination


def render_verify_command(destination: str) -> str:
    return f"verify {shell_quote(flash_verify_path(destination))}"


def redact_access_token(text: str) -> str:
    return ACCESS_TOKEN_PATTERN.sub(r"\1<redacted>", text)


def sanitize_log_text(text: str, limit: int = 500) -> str:
    sanitized = redact_access_token(text)
    sanitized = re.sub(r"[\s\x00-\x1f\x7f-\x9f]+", " ", sanitized).strip()
    if len(sanitized) <= limit:
        return sanitized
    marker = "...[truncated]"
    if limit <= 0:
        return ""
    if limit <= len(marker):
        return marker[:limit]
    return sanitized[:limit - len(marker)].rstrip() + marker


def log_step(ctx: Any, operation: str, status: str, detail: str) -> None:
    if status not in LOG_STATUSES:
        raise ValueError(f"unknown log status: {status}")
    ctx.info(f"Step: {operation} | Status: {status} | {detail}")


def response_payload(response: Any) -> Any:
    json_reader = getattr(response, "json", None)
    if json_reader:
        try:
            return json_reader()
        except Exception:
            return response
    return response


def command_errors(response: Any) -> List[str]:
    payload = response_payload(response)
    if isinstance(payload, dict) and all(key in payload for key in ("errorCode", "errorMessage")):
        return [redact_access_token(f"{payload['errorCode']}: {payload['errorMessage']}")]
    errors = []
    records = payload if isinstance(payload, list) else [payload]
    for record in records:
        if not isinstance(record, dict):
            continue
        error = string_value(record.get("error"))
        if error:
            errors.append(redact_access_token(error))
    return errors


def bool_arg(value: Any) -> bool:
    return str(value or "").strip().casefold() in ("1", "true", "yes", "y", "on")


def auto_arg(value: Any) -> str:
    text = str(value or "").strip()
    if text.casefold() in AUTO_VALUES:
        return ""
    return text


def action_arg(args: Dict[str, Any], *names: str) -> str:
    for name in names:
        if name in args:
            return auto_arg(args.get(name))
    return ""


def ctx_args(ctx: Any) -> Dict[str, Any]:
    action = getattr(ctx, "action", None)
    return getattr(action, "args", {}) or {}


def ctx_device(ctx: Any) -> Any:
    getter = getattr(ctx, "getDevice", None)
    return getter() if getter else getattr(ctx, "device", None)


def get_device_id(ctx: Any, args: Dict[str, Any]) -> str:
    device = ctx_device(ctx)
    device_id = args.get("DeviceID") or getattr(device, "id", "")
    if not device_id:
        raise ValueError("Action must run with a selected device")
    return device_id


def extract_ip_address(record: Any) -> str:
    return first_string(record, IP_FIELDS)


def get_source_ip(ctx: Any, args: Dict[str, Any], device_id: str) -> str:
    source_ip = action_arg(args, "Source IP", "source_ip")
    if source_ip:
        return source_ip
    errors = []
    try:
        source_ip = extract_ip_address(load_provisioned_device(ctx, device_id))
    except Exception as err:
        errors.append(str(err))
        source_ip = ""
    if source_ip:
        return source_ip
    device = ctx_device(ctx)
    source_ip = getattr(device, "ip", "")
    if not source_ip:
        raise ValueError(
            "Source IP could not be determined from CloudVision ProvisionedDevice state: "
            + "; ".join(errors)
        )
    return source_ip


def get_authority(ctx: Any, args: Dict[str, Any]) -> str:
    authority = action_arg(args, "authority", "Authority")
    if authority:
        return normalize_authority(authority)
    connections = getattr(ctx, "connections", None)
    for field in ("apiserverAddr", "serviceAddr"):
        value = getattr(connections, field, "") if connections else ""
        if value and not is_internal_authority(value):
            return normalize_authority(value, strip_ports=API_SERVER_PORTS)
    raise ValueError("CloudVision authority could not be determined; set authority explicitly")


def get_access_token(ctx: Any) -> str:
    user = getattr(ctx, "user", None)
    token = getattr(user, "token", "")
    if not token:
        raise ValueError("CloudVision access token is unavailable in the action context")
    return token


def cv_resource_get_all(ctx: Any, services_module: str, service_stub: str,
                        request_name: str) -> List[Any]:
    getter = getattr(ctx, "getApiClient", None)
    if not getter:
        raise ValueError("CloudVision Resource API client is unavailable")
    services = import_module(services_module)
    stub_class = getattr(services, service_stub)
    request_class = getattr(services, request_name)
    stub = getter(stub_class)
    return [
        resource_response_value(response)
        for response in stub.GetAll(request_class(), timeout=RESOURCE_API_TIMEOUT)
    ]


def cv_resource_get_one(ctx: Any, services_module: str, models_module: str,
                        service_stub: str, request_name: str, key_name: str,
                        key_field: str, key_value: str) -> Any:
    getter = getattr(ctx, "getApiClient", None)
    if not getter:
        raise ValueError("CloudVision Resource API client is unavailable")
    services = import_module(services_module)
    models = import_module(models_module)
    stub_class = getattr(services, service_stub)
    request_class = getattr(services, request_name)
    key_class = getattr(models, key_name)
    key = key_class(**{key_field: wrapped_string(key_value)})
    stub = getter(stub_class)
    return resource_response_value(
        stub.GetOne(request_class(key=key), timeout=RESOURCE_API_TIMEOUT)
    )


def cv_resource_get_all_available(ctx: Any, resources: Iterable[Tuple[str, str, str, str]],
                                  description: str) -> List[Any]:
    records = []
    errors = []
    for services_module, service_stub, request_name, label in resources:
        try:
            records.extend(cv_resource_get_all(ctx, services_module, service_stub, request_name))
        except Exception as err:
            errors.append(f"{label}: {err}")
    if records:
        return records
    raise ValueError(f"Unable to read {description}: " + "; ".join(errors))


def load_repository(ctx: Any) -> Any:
    return cv_resource_get_all_available(
        ctx,
        (
            (
                "arista.softwaremanagement.v1.services",
                "RepositoryServiceStub",
                "RepositoryStreamRequest",
                "Repository",
            ),
            (
                "arista.softwaremanagement.v1.services",
                "RepositoryConfigServiceStub",
                "RepositoryConfigStreamRequest",
                "RepositoryConfig",
            ),
        ),
        "Software Management repository",
    )


def load_image_summary(ctx: Any, device_id: str) -> Any:
    return cv_resource_get_one(
        ctx,
        "arista.imagestatus.v1.services",
        "arista.imagestatus.v1",
        "SummaryServiceStub",
        "SummaryRequest",
        "SummaryKey",
        "device_id",
        device_id,
    )


def load_running(ctx: Any, device_id: str) -> Any:
    return cv_resource_get_one(
        ctx,
        "arista.inventory.v1.services",
        "arista.inventory.v1",
        "DeviceServiceStub",
        "DeviceRequest",
        "DeviceKey",
        "device_id",
        device_id,
    )


def load_provisioned_device(ctx: Any, device_id: str) -> Any:
    return cv_resource_get_one(
        ctx,
        "arista.inventory.v1.services",
        "arista.inventory.v1",
        "ProvisionedDeviceServiceStub",
        "ProvisionedDeviceRequest",
        "DeviceKey",
        "device_id",
        device_id,
    )


def run_device_cmds(ctx: Any, commands: List[str], **kwargs: Any) -> Any:
    runner = getattr(ctx, "runDeviceCmds", None)
    if not runner:
        raise ValueError("Device command execution is unavailable in this action context")
    return runner(commands, **kwargs)


def detect_vrf(ctx: Any, source_ip: str) -> str:
    grep_ip = shell_quote(f" {source_ip}/")
    script = (
        "for ns in $(sudo ip netns list | awk '{print $1}'); do "
        f"sudo ip netns exec \"$ns\" ip -o addr show | grep -q -- {grep_ip} "
        "&& echo \"${ns#ns-}\" && exit 0; "
        "done; "
        f"ip -o addr show | grep -q -- {grep_ip} && echo default || true"
    )
    try:
        responses = run_device_cmds(
            ctx,
            ["enable", render_bash_command(script)],
            fmt="text",
            validateResponse=False,
            timeout=120,
            diCliTimeout=120,
        )
    except Exception:
        return ""
    lines = [line.strip() for line in first_response_text(responses).splitlines()]
    lines = [line for line in lines if line]
    if lines:
        return lines[0]
    return ""


def get_vrf(ctx: Any, args: Dict[str, Any], source_ip: str) -> str:
    vrf = action_arg(args, "VRF", "vrf")
    if vrf:
        return vrf
    return detect_vrf(ctx, source_ip) or DEFAULT_VRF


def set_info_logging(ctx: Any) -> Any:
    getter = getattr(ctx, "getLoggingLevel", None)
    setter = getattr(ctx, "setLoggingLevel", None)
    if not getter or not setter:
        return None
    previous_level = getter()
    try:
        from cloudvision.cvlib.context import LoggingLevel
        setter(LoggingLevel.Info)
    except Exception:
        return None
    return previous_level


def restore_logging(ctx: Any, previous_level: Any) -> None:
    if previous_level is None:
        return
    setter = getattr(ctx, "setLoggingLevel", None)
    if setter:
        setter(previous_level)


def run_transfer_command(ctx: Any, command: str) -> None:
    previous_level = set_info_logging(ctx)
    try:
        response = run_device_cmds(
            ctx,
            ["enable", command],
            fmt="text",
            validateResponse=False,
            timeout=DEFAULT_TIMEOUT + 300,
            diCliTimeout=DEFAULT_TIMEOUT + 300,
            diConnTimeout=DEFAULT_TIMEOUT + 300,
        )
    finally:
        restore_logging(ctx, previous_level)

    errors = command_errors(response)
    if errors:
        raise ValueError(f"Preload transfer command failed: {errors[0]}")


def get_existing_size(ctx: Any, destination: str) -> Optional[int]:
    quoted_destination = shell_quote(destination)
    command = render_bash_command(
        f"test -f {quoted_destination} && stat -c %s {quoted_destination} || true"
    )
    responses = run_device_cmds(
        ctx,
        ["enable", command],
        fmt="text",
        timeout=120,
        diCliTimeout=120,
    )
    return parse_existing_size(responses)


def remove_existing_target(ctx: Any, destination: str) -> None:
    command = render_bash_command(
        f"rm -f -- {shell_quote(destination)}"
    )
    run_device_cmds(ctx, ["enable", command], fmt="text", timeout=120, diCliTimeout=120)


def ensure_destination_parent(ctx: Any, destination: str) -> None:
    parent = dirname(destination)
    if not parent:
        return
    command = render_bash_command(f"mkdir -p -- {shell_quote(parent)}")
    run_device_cmds(ctx, ["enable", command], fmt="text", timeout=120, diCliTimeout=120)


def get_target_checksum(ctx: Any, destination: str, algorithm: str) -> str:
    destination_path = shell_quote(destination)
    command = render_bash_command(
        f"test -s {destination_path} && {algorithm}sum {destination_path}",
        timeout=DEFAULT_TIMEOUT,
    )
    responses = run_device_cmds(
        ctx,
        ["enable", command],
        fmt="text",
        validateResponse=False,
        timeout=DEFAULT_TIMEOUT,
        diCliTimeout=DEFAULT_TIMEOUT,
    )
    errors = command_errors(responses)
    if errors:
        raise ValueError(errors[0])
    checksum = parse_checksum(responses)
    if not checksum:
        raise ValueError(f"Unable to read {algorithm} checksum for {destination}")
    return checksum


def verify_eos_image(ctx: Any, destination: str) -> str:
    command = render_verify_command(destination)
    responses = run_device_cmds(
        ctx,
        ["enable", command],
        fmt="text",
        validateResponse=False,
        timeout=DEFAULT_TIMEOUT,
        diCliTimeout=DEFAULT_TIMEOUT,
    )
    errors = command_errors(responses)
    if errors:
        raise ValueError(errors[0])
    return first_response_text(responses)


def target_is_verified(ctx: Any, artifact: Artifact, destination: str,
                       existing_size: Optional[int] = None) -> bool:
    size = existing_size
    if size is None:
        size = get_existing_size(ctx, destination)
    if size is None or size <= 0:
        return False
    if is_eos_verifiable_artifact(artifact):
        try:
            verify_eos_image(ctx, destination)
        except Exception:
            return False
        return True
    algorithm, expected = expected_checksum(artifact)
    try:
        actual = get_target_checksum(ctx, destination, algorithm)
    except Exception:
        return False
    if expected:
        return actual == expected
    return bool(actual)


def verify_download(ctx: Any, artifact: Artifact, destination: str) -> None:
    existing_size = get_existing_size(ctx, destination)
    if existing_size is None:
        raise ValueError(f"Download did not create {destination}")
    if existing_size <= 0:
        raise ValueError(f"Downloaded file is empty: {destination}")
    if is_eos_verifiable_artifact(artifact):
        operation = (
            "EOS image verification"
            if is_swi_artifact(artifact) else "EOS package verification"
        )
        context = f"Artifact: {artifact.filename}; Destination: {destination}"
        log_step(
            ctx,
            operation,
            LOG_STATUS_STARTED,
            f"{context}; Device verify command: {render_verify_command(destination)}",
        )
        try:
            response_text = verify_eos_image(ctx, destination)
        except Exception as err:
            log_step(
                ctx,
                operation,
                LOG_STATUS_ERROR,
                sanitize_log_text(f"{context}; Error: {err}"),
            )
            raise
        detail = sanitize_log_text(response_text)
        if detail:
            log_step(
                ctx,
                operation,
                LOG_STATUS_SUCCESS,
                f"{context}; Device response: {detail}",
            )
        else:
            log_step(
                ctx,
                operation,
                LOG_STATUS_SUCCESS,
                f"{context}; Device response: "
                "(none; absence of Command API error confirms success).",
            )
        return
    algorithm, expected = expected_checksum(artifact)
    operation = "Checksum verification"
    context = (
        f"Algorithm: {algorithm}; Artifact: {artifact.filename}; "
        f"Destination: {destination}"
    )
    log_step(ctx, operation, LOG_STATUS_STARTED, context)
    try:
        actual = get_target_checksum(ctx, destination, algorithm)
        if expected and actual != expected:
            raise ValueError(
                f"Downloaded file checksum mismatch for {destination}: "
                f"expected {algorithm} {expected}, got {actual}"
            )
    except Exception as err:
        log_step(
            ctx,
            operation,
            LOG_STATUS_ERROR,
            sanitize_log_text(f"{context}; Error: {err}"),
        )
        raise
    detail = (
        "checksum matches the repository digest."
        if expected else "checksum is readable; no repository digest was available."
    )
    log_step(
        ctx,
        operation,
        LOG_STATUS_SUCCESS,
        f"{context}; Detail: {detail}",
    )


def preload_artifact(ctx: Any, artifact: Artifact, destination: str, authority: str,
                     vrf: str, source_ip: str, token: str, force: bool) -> None:
    preload_operation = "Artifact preload"
    preload_context = (
        f"Artifact: {artifact.filename}; Repository path: {artifact.file_server_path}; "
        f"Destination: {destination}"
    )
    log_step(ctx, preload_operation, LOG_STATUS_STARTED, preload_context)
    try:
        url = build_file_api_url(authority, artifact.file_server_path)
        existing_size = get_existing_size(ctx, destination)
        verified = (
            target_is_verified(ctx, artifact, destination, existing_size)
            if existing_size is not None and not force else False
        )
        plan = plan_download(existing_size, verified, force)
        target_context = (
            f"Artifact: {artifact.filename}; Destination: {destination}; "
            f"Reason: {plan.reason}"
        )
        if plan.action == "skip":
            log_step(
                ctx,
                preload_operation,
                LOG_STATUS_SKIPPED,
                f"{preload_context}; Reason: {plan.reason}",
            )
            return
        if plan.action == "rewrite" and existing_size is not None:
            log_step(
                ctx,
                "Existing target handling",
                LOG_STATUS_WARNING,
                f"{target_context}; Detail: existing target will be replaced.",
            )
            cleanup_operation = "Existing target cleanup"
            cleanup_context = (
                f"Artifact: {artifact.filename}; Destination: {destination}"
            )
            log_step(
                ctx,
                cleanup_operation,
                LOG_STATUS_STARTED,
                cleanup_context,
            )
            try:
                remove_existing_target(ctx, destination)
            except Exception as err:
                log_step(
                    ctx,
                    cleanup_operation,
                    LOG_STATUS_ERROR,
                    sanitize_log_text(f"{cleanup_context}; Error: {err}"),
                )
                raise
            log_step(
                ctx,
                cleanup_operation,
                LOG_STATUS_SUCCESS,
                f"{cleanup_context}; Detail: existing target removed.",
            )

        ensure_destination_parent(ctx, destination)
        command = render_artifact_preload_command(
            artifact, url, destination, vrf, source_ip, token
        )
        redacted_command = render_artifact_preload_command(
            artifact, url, destination, vrf, source_ip, token, redacted=True
        )
        transfer_operation = "Artifact transfer"
        transfer_context = (
            f"Artifact: {artifact.filename}; Source: {url}; Destination: {destination}"
        )
        log_step(
            ctx,
            transfer_operation,
            LOG_STATUS_STARTED,
            f"{transfer_context}; Device transfer command: {redacted_command}",
        )
        try:
            run_transfer_command(ctx, command)
        except Exception as err:
            log_step(
                ctx,
                transfer_operation,
                LOG_STATUS_ERROR,
                sanitize_log_text(f"{transfer_context}; Error: {err}"),
            )
            raise
        log_step(
            ctx,
            transfer_operation,
            LOG_STATUS_SUCCESS,
            f"{transfer_context}; Detail: transfer command completed.",
        )
        verify_download(ctx, artifact, destination)
    except Exception as err:
        log_step(
            ctx,
            preload_operation,
            LOG_STATUS_ERROR,
            sanitize_log_text(f"{preload_context}; Error: {err}"),
        )
        raise
    log_step(
        ctx,
        preload_operation,
        LOG_STATUS_SUCCESS,
        f"{preload_context}; Detail: artifact was transferred and verified.",
    )


def run(ctx: Any) -> None:
    args = ctx_args(ctx)
    source = str(args.get("Source") or args.get("source") or DEFAULT_SOURCE).strip().casefold()
    source = source or DEFAULT_SOURCE
    repository_image = action_arg(args, "Repository Image", "repository_image")
    repository_agent = action_arg(
        args, "Repository Streaming Agent", "repository_streaming_agent"
    )
    repository_extensions = action_arg(
        args, "Repository Extensions", "repository_extensions"
    )
    ignored_fields = [
        field for field, value in (
            ("Repository Image", repository_image),
            ("Repository Streaming Agent", repository_agent),
            ("Repository Extensions", repository_extensions),
        ) if value
    ]
    if ignored_fields and source not in ("repository", "explicit"):
        if len(ignored_fields) == 1:
            field_text = ignored_fields[0]
            ignored_text = "this input is ignored"
        elif len(ignored_fields) == 2:
            field_text = " and ".join(ignored_fields)
            ignored_text = "these inputs are ignored"
        else:
            field_text = ", ".join(ignored_fields[:-1]) + ", and " + ignored_fields[-1]
            ignored_text = "these inputs are ignored"
        log_step(
            ctx,
            "Parameter check",
            LOG_STATUS_WARNING,
            f"{field_text} provided but Source is '{source}'; {ignored_text}.",
        )
    force = bool_arg(args.get("force") or args.get("Force"))
    device_id = get_device_id(ctx, args)
    artifacts = resolve_runtime_artifacts(
        ctx,
        source,
        device_id,
        repository_image,
        repository_agent,
        repository_extensions,
    )
    destination_override = action_arg(args, "Destination", "destination")
    destinations = [
        (artifact, destination_for_artifact(artifact, destination_override, index))
        for index, artifact in enumerate(artifacts)
    ]
    destination_artifacts = {}
    for artifact, destination in destinations:
        previous = destination_artifacts.get(destination)
        if (
            previous
            and previous.file_server_path.casefold() != artifact.file_server_path.casefold()
        ):
            raise ValueError(
                f"Destination collision: artifacts '{previous.filename}' "
                f"and '{artifact.filename}' map to destination '{destination}'"
            )
        destination_artifacts[destination] = artifact

    source_ip = get_source_ip(ctx, args, device_id)
    vrf = get_vrf(ctx, args, source_ip)
    authority = get_authority(ctx, args)
    token = get_access_token(ctx)
    for artifact, destination in destinations:
        preload_artifact(ctx, artifact, destination, authority, vrf, source_ip, token, force)


if "ctx" in globals():
    try:
        run(ctx)
    except Exception as exc:
        from cloudvision.cvlib import ActionFailed
        raise ActionFailed(str(exc))
