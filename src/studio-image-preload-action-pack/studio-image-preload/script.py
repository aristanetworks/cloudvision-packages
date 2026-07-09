# Copyright (c) 2026 Arista Networks, Inc.
# Use of this source code is governed by the Apache License 2.0
# that can be found in the COPYING file.

import re
from dataclasses import dataclass
from posixpath import basename
from shlex import quote as shell_quote
from typing import Any, Dict, Iterable, List, Optional
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
FLASH_ROOT = "/mnt/flash"

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
DESIGNED_FIELDS = (
    "designedImage",
    "designed_image",
    "targetImage",
    "target_image",
    "assignedImage",
    "assigned_image",
    "softwareImage",
    "software_image",
    "imageName",
    "image_name",
    "name",
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
SHA512_FIELDS = ("sha512", "sha512sum", "sha512Sum", "sha512Checksum")
MD5_FIELDS = ("md5", "md5sum", "md5Sum", "md5Checksum")
DEVICE_FIELDS = ("deviceId", "device_id", "deviceIds", "device_ids", "devices")


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


def normalize_authority(authority: str) -> str:
    cleaned = authority.strip()
    if not cleaned:
        raise ValueError("CloudVision authority could not be determined")
    parsed = urlparse(cleaned)
    if parsed.scheme:
        cleaned = parsed.netloc
    return cleaned.rstrip("/")


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
    if "/" not in path:
        raise ValueError("Software Management file path is incomplete")
    return path


def build_file_api_url(authority: str, file_server_path: str) -> str:
    normalized = normalize_file_server_path(file_server_path)
    encoded = "/".join(url_quote(part, safe="") for part in normalized.split("/"))
    return f"https://{normalize_authority(authority)}/api/v1/files/{encoded}"


def parse_version_from_filename(filename: str) -> str:
    stem = basename(filename)
    for prefix in ("EOS64-", "EOSarm-", "EOS-"):
        if stem.startswith(prefix) and stem.endswith(".swi"):
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
    records = repository if isinstance(repository, list) else [repository]
    artifacts = []
    for record in records:
        artifact = extract_artifact(record)
        if artifact:
            artifacts.append(artifact)
    return artifacts


def contains_device_id(record: Any, device_id: str) -> bool:
    if not device_id:
        return True
    for item in iter_dicts(unwrap_resource(record)):
        for value in item.values():
            if value == device_id:
                return True
            if isinstance(value, list) and device_id in value:
                return True
            if isinstance(value, dict) and value.get("value") == device_id:
                return True
    return False


def has_device_reference(record: Any) -> bool:
    for item in iter_dicts(unwrap_resource(record)):
        if any(field in item for field in DEVICE_FIELDS):
            return True
    return False


def record_applies_to_device(record: Any, device_id: str) -> bool:
    return contains_device_id(record, device_id) or not has_device_reference(record)


def designed_artifact(designed: Any, device_id: str) -> Optional[Artifact]:
    records = designed if isinstance(designed, list) else [designed]
    for record in records:
        if not record_applies_to_device(record, device_id):
            continue
        artifact = extract_artifact(record)
        if artifact:
            return artifact
    return None


def designed_identifier(designed: Any, device_id: str) -> str:
    records = designed if isinstance(designed, list) else [designed]
    for record in records:
        if not record_applies_to_device(record, device_id):
            continue
        artifact = extract_artifact(record)
        if artifact:
            return artifact.filename
        value = first_string(record, DESIGNED_FIELDS)
        if value:
            return value
    return ""


def running_identifier(running: Any) -> str:
    artifact = extract_artifact(running)
    if artifact:
        return artifact.filename
    return first_string(running, RUNNING_FIELDS)


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
        raise ValueError(f"Repository image selector '{selector}' matched multiple images: {names}")
    return matches[0]


def resolve_artifact(source: str, device_id: str, repository: Any, designed: Any,
                     running: Any, repository_image: str) -> Artifact:
    artifacts = artifacts_from_repository(repository)
    mode = (source or DEFAULT_SOURCE).strip().casefold()

    if mode == "designed":
        artifact = designed_artifact(designed, device_id)
        if artifact:
            return artifact
        selector = designed_identifier(designed, device_id)
        if not selector:
            raise ValueError(f"No designed Software Management image found for {device_id}")
        return find_artifact(artifacts, selector)

    if mode == "running":
        selector = running_identifier(running)
        if not selector:
            raise ValueError(f"No running EOS image found for {device_id}")
        return find_artifact(artifacts, selector)

    if mode in ("repository", "explicit"):
        if not repository_image.strip():
            raise ValueError("Repository source requires a repository image name or version")
        return find_artifact(artifacts, repository_image)

    raise ValueError("source must be one of designed, running, or repository")


def default_destination(filename: str) -> str:
    return f"{FLASH_ROOT}/{basename(filename)}"


def render_preload_command(url: str, destination: str, vrf: str, source_ip: str,
                           token: str, redacted: bool = False,
                           timeout: int = DEFAULT_TIMEOUT,
                           speed_time: int = DEFAULT_SPEED_TIME,
                           speed_limit: int = DEFAULT_SPEED_LIMIT) -> str:
    cookie_value = "<redacted>" if redacted else token
    netns = f"ns-{vrf}"
    return " ".join((
        "bash",
        "timeout",
        str(timeout),
        "sudo",
        "ip",
        "netns",
        "exec",
        shell_quote(netns),
        "curl",
        shell_quote(url),
        "--insecure",
        "--cookie",
        f'"access_token={cookie_value}"',
        "--fail",
        "--speed-time",
        str(speed_time),
        "--speed-limit",
        str(speed_limit),
        "-sS",
        "--interface",
        shell_quote(source_ip),
        "|",
        "/export/swi/swadapt",
        shell_quote(destination),
    ))


def plan_download(existing_size: Optional[int], artifact: Artifact, force: bool) -> DownloadPlan:
    if force:
        return DownloadPlan("rewrite", "force requested")
    if existing_size is None:
        return DownloadPlan("download", "target file is absent")
    if artifact.size is None:
        if existing_size > 0:
            return DownloadPlan("skip", "target file exists and repository size is unavailable")
        return DownloadPlan("rewrite", "target file exists but has zero size")
    if existing_size == artifact.size:
        return DownloadPlan("skip", "target file already matches repository size")
    return DownloadPlan("rewrite", "target file size differs from repository size")


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


def redact_access_token(text: str) -> str:
    return ACCESS_TOKEN_PATTERN.sub(r"\1<redacted>", text)


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


def get_source_ip(ctx: Any, args: Dict[str, Any]) -> str:
    source_ip = args.get("Source IP") or args.get("source_ip")
    if source_ip:
        return source_ip.strip()
    device = ctx_device(ctx)
    source_ip = getattr(device, "ip", "")
    if not source_ip:
        raise ValueError("Source IP could not be determined from the selected device")
    return source_ip


def get_authority(ctx: Any, args: Dict[str, Any]) -> str:
    authority = args.get("authority") or args.get("Authority")
    if authority:
        return normalize_authority(authority)
    connections = getattr(ctx, "connections", None)
    for field in ("apiserverAddr", "serviceAddr"):
        value = getattr(connections, field, "") if connections else ""
        if value:
            return normalize_authority(value)
    raise ValueError("CloudVision authority could not be determined; set authority explicitly")


def get_access_token(ctx: Any) -> str:
    user = getattr(ctx, "user", None)
    token = getattr(user, "token", "")
    if not token:
        raise ValueError("CloudVision access token is unavailable in the action context")
    return token


def cv_http_get(ctx: Any, path: str) -> Any:
    getter = getattr(ctx, "httpGet", None)
    if not getter:
        raise ValueError("CloudVision HTTP API is unavailable in this action context")
    return getter(path)


def load_repository(ctx: Any) -> Any:
    return cv_http_get(ctx, "/api/resources/softwaremanagement/v1/Repository/all")


def load_designed(ctx: Any, device_id: str) -> Any:
    encoded_device = url_quote(device_id, safe="")
    paths = (
        f"/api/resources/imagestatus/v1/Summary?key.deviceId={encoded_device}",
        "/api/resources/softwaremanagement/v1/Assignments/all",
    )
    errors = []
    for path in paths:
        try:
            return cv_http_get(ctx, path)
        except Exception as err:
            errors.append(str(err))
    raise ValueError("Unable to read designed image state: " + "; ".join(errors))


def load_running(ctx: Any, device_id: str) -> Any:
    encoded_device = url_quote(device_id, safe="")
    return cv_http_get(ctx, f"/api/resources/inventory/v1/Device?key.deviceId={encoded_device}")


def run_device_cmds(ctx: Any, commands: List[str], **kwargs: Any) -> Any:
    runner = getattr(ctx, "runDeviceCmds", None)
    if not runner:
        raise ValueError("Device command execution is unavailable in this action context")
    return runner(commands, **kwargs)


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
    command = f"bash test -f {quoted_destination} && stat -c %s {quoted_destination} || true"
    responses = run_device_cmds(
        ctx,
        ["enable", command],
        fmt="text",
        timeout=120,
        diCliTimeout=120,
    )
    return parse_existing_size(responses)


def remove_existing_target(ctx: Any, destination: str) -> None:
    command = f"bash rm -f -- {shell_quote(destination)}"
    run_device_cmds(ctx, ["enable", command], fmt="text", timeout=120, diCliTimeout=120)


def verify_download(ctx: Any, artifact: Artifact, destination: str) -> None:
    existing_size = get_existing_size(ctx, destination)
    if existing_size is None:
        raise ValueError(f"Download did not create {destination}")
    if artifact.size is not None and existing_size != artifact.size:
        raise ValueError(
            f"Downloaded file size mismatch for {destination}: "
            f"expected {artifact.size}, got {existing_size}"
        )


def run(ctx: Any) -> None:
    args = ctx_args(ctx)
    source = args.get("Source") or args.get("source") or DEFAULT_SOURCE
    repository_image = args.get("Repository Image") or args.get("repository_image") or ""
    force = bool_arg(args.get("force") or args.get("Force"))
    vrf = (args.get("VRF") or args.get("vrf") or DEFAULT_VRF).strip()
    device_id = get_device_id(ctx, args)
    source_ip = get_source_ip(ctx, args)
    authority = get_authority(ctx, args)
    token = get_access_token(ctx)

    repository = load_repository(ctx)
    designed = load_designed(ctx, device_id) if source.casefold() == "designed" else {}
    running = load_running(ctx, device_id) if source.casefold() == "running" else {}
    artifact = resolve_artifact(source, device_id, repository, designed, running, repository_image)
    if not artifact.filename.endswith(".swi"):
        raise ValueError(f"Only SWI image preload is supported, got {artifact.filename}")

    destination = args.get("Destination") or args.get("destination") or default_destination(
        artifact.filename
    )
    url = build_file_api_url(authority, artifact.file_server_path)
    existing_size = get_existing_size(ctx, destination)
    plan = plan_download(existing_size, artifact, force)
    if plan.action == "skip":
        ctx.info(f"Skipping preload of {artifact.filename}: {plan.reason}")
        return
    if plan.action == "rewrite" and existing_size is not None:
        ctx.info(f"Removing existing {destination}: {plan.reason}")
        remove_existing_target(ctx, destination)

    command = render_preload_command(url, destination, vrf, source_ip, token)
    redacted_command = render_preload_command(
        url, destination, vrf, source_ip, token, redacted=True
    )
    ctx.info(f"Preloading {artifact.filename} from {url} to {destination}")
    ctx.info(f"Device transfer command: {redacted_command}")
    run_transfer_command(ctx, command)
    verify_download(ctx, artifact, destination)
    ctx.info(f"Preloaded {artifact.filename} to {destination}")


if "ctx" in globals():
    try:
        run(ctx)
    except Exception as exc:
        from cloudvision.cvlib import ActionFailed
        raise ActionFailed(str(exc))
