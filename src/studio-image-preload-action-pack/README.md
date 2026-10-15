# Studio Image Preload Action Pack

This package adds the `Studio Image Preload` change-control action. The action
preloads Software Management artifacts from CloudVision onto the selected
device and stops there. For a Studio-designed source this includes the EOS SWI,
the explicitly selected streaming-agent package when external, and the ordered
designed extension packages. It does not set boot variables, install
extensions, schedule a reload, call Set Image, or perform an upgrade.

The transfer uses the modern CloudVision file API:

```text
https://<cvp>/api/v1/files/software/<uuid>/<filename>
```

It intentionally does not use the legacy
`/cvpservice/image/getImagebyId/` endpoint.

## CloudVision State Used

The action resolves defaults from CloudVision at runtime using generated
CloudVision Resource API clients from the action context. It does not call
`ctx.httpGet` for these state reads, because that runtime path can resolve to
an internal Kubernetes service address that is not the CVP authority operators
expect to see.

```text
softwaremanagement.v1.Repository
softwaremanagement.v1.RepositoryConfig
studio.v1.Inputs
studio.v1.InputsConfig
inventory.v1.Device
inventory.v1.ProvisionedDevice
imagestatus.v1.Summary (running mode only)
```

Repository state is preferred when available because it exposes the Software
Management `fileServerPath`, size, and digest metadata. Repository config is
also read so locally uploaded records with `/software/<uuid>/<filename>` URIs
work on CloudVision releases where repository state is unavailable. Repository
records cover images and extensions.

For designed mode, the authoritative record is the committed root/mainline
Software Management Studio `studio.v1.Inputs` record: `workspaceId` must be
`""` and the path must be the root path. Workspace drafts are ignored. The
record contains the user-facing Software Assignment and Software Settings.
Inputs larger than 1 MB may be returned as same-root fragments; the action
reconstructs those fragments in their returned order before parsing the JSON.

## Source Modes

`designed` is the default. It reads the committed root/mainline Studio
Software Assignment and Software Settings described above, then selects
exactly one pure device assignment for the action device. A pure device
assignment is an explicit device-only assignment; designed mode does not infer
membership from tags or from another CloudVision state source.

The selected Software Settings must contain a non-empty image. The streaming
agent is an explicit decision: `null` or an empty value means Embedded and no
separate artifact is included; a non-empty filename means an external agent
and that repository artifact is included. Extensions are a strict ordered
zero-or-more list. Zero means that no extension artifacts are included. Every
entry must be a non-empty, well-formed entry; a malformed or empty entry
fails, and its repository artifact must resolve exactly once.

Missing, ambiguous, or malformed assignments, settings, or repository
artifacts fail before transfer. There is no inferred backfill, image-only
fallback, or designed-image lookup from running-image summary state.

`running` resolves the device's currently reported running EOS image from image
summary state when available, otherwise it uses the running `softwareVersion`
from CloudVision inventory and matches that version to a Software Management
repository artifact.

`repository` resolves three operator inputs against the Software Management
repository:

- `Repository Image` is required and accepts a human-friendly artifact filename
  or version, such as `EOS-4.34.7M.swi` or `4.34.7M`.
- `Repository Streaming Agent` is optional. It selects an external TerminAttr
  artifact; empty or `auto` means the EOS embedded agent, so no agent file is
  preloaded.
- `Repository Extensions` is optional and accepts a comma-separated list of
  zero, one, or many artifact names or versions. Whitespace around commas is
  ignored; empty or `auto` means no extensions.

Do not provide raw file-server paths. Every non-empty image, agent, or
extension selector must resolve to exactly one repository artifact; an
unresolved or ambiguous selector fails the action hard. In a multi-artifact
preload, a custom `Destination` applies to the image at index 0. The selected
agent and extensions use their artifact filenames under `/mnt/flash` (or the
same directory when `Destination` ends in `/`). Destination collisions are
rejected before any transfer starts.

## Designed resolution diagnostics

Every successful `designed` run emits one `Designed resolution` diagnostic.
It states that the committed mainline Software Assignment matched, the image
decision, the explicit streaming-agent decision, the ordered extension count
and filenames, and the final artifact set. A missing, ambiguous, or malformed
designed input fails before this success diagnostic is emitted.

An external TerminAttr with zero extensions is summarized exactly like this:

```text
Step: Designed resolution | Status: SUCCESS | Software Assignment: matched committed mainline assignment for JPE00000001; Image decision: EOS-4.34.6M.swi configured; include EOS-4.34.6M.swi; Streaming agent decision: external TerminAttr-1.40.10-1.swix configured; include TerminAttr-1.40.10-1.swix; Extensions decision: 0 configured; no extension artifacts included; Final: EOS-4.34.6M.swi (image), TerminAttr-1.40.10-1.swix (agent)
```

The image and external TerminAttr are included because the image is required
and the agent filename is non-empty. No extension transfer occurs because the
committed extension list has zero entries.

An embedded-agent design with no extensions is summarized exactly like this:

```text
Step: Designed resolution | Status: SUCCESS | Software Assignment: matched committed mainline assignment for JPE00000001; Image decision: EOS-4.34.6M.swi configured; include EOS-4.34.6M.swi; Streaming agent decision: embedded configured; no separate streaming-agent artifact included; Extensions decision: 0 configured; no extension artifacts included; Final: EOS-4.34.6M.swi (image)
```

Only the EOS image is included in this case: null or empty streaming-agent
settings explicitly select the embedded agent, and the zero-length extension
list explicitly selects no extensions.

For an external agent and two ordered extensions, the current format is:

```text
Step: Designed resolution | Status: SUCCESS | Software Assignment: matched committed mainline assignment for JPE00000001; Image decision: EOS-4.34.6M.swi configured; include EOS-4.34.6M.swi; Streaming agent decision: external TerminAttr-1.40.10-1.swix configured; include TerminAttr-1.40.10-1.swix; Extensions decision: 2 configured; include switchapp-1.15.1-1.10.swix, otheragent-2.0.swix; Final: EOS-4.34.6M.swi (image), TerminAttr-1.40.10-1.swix (agent), switchapp-1.15.1-1.10.swix (extension), otheragent-2.0.swix (extension)
```

This produces four ordered artifact transfers: image, external agent,
`switchapp-1.15.1-1.10.swix`, then `otheragent-2.0.swix`.

## Defaults

Use `auto` for `authority` to use the device-reachable CloudVision API server
from the action runtime context. The action avoids the internal Kubernetes
ambassador service address for device-side transfers, and strips the action
runtime API-server port `9900` from automatically discovered authorities so
device curl uses the HTTPS file API. Set this only if the runtime context does
not expose a switch-reachable CloudVision address. Explicit authority values
preserve any operator-provided port.

`VRF` defaults to `auto`. The action asks the device, through CloudVision
command execution, which Linux namespace contains the CVP-managed source IP. If
the source IP is in the device default namespace, the transfer omits `ip netns
exec`. If detection is unavailable, it falls back to `MGMT`, producing
`ns-MGMT`.

`Source IP` defaults to `auto`, which uses
`inventory.v1.ProvisionedDevice` for the selected device's CloudVision-managed
IP address.

`Destination` defaults to `auto`, which resolves to `/mnt/flash/<artifact filename>`.
When any source resolves multiple artifacts, a custom destination only applies
to the first EOS image artifact; TerminAttr and extension artifacts use their
repository filenames under `/mnt/flash`. A destination ending in `/` is
treated as a directory and the artifact filename is appended, for example
`/mnt/flash/test/` becomes `/mnt/flash/test/EOS-4.34.7M.swi` for the image and
corresponding filenames for the other artifacts. The action creates the
destination parent directory before downloading and rejects destination
collisions before the first transfer.

The curl guardrails match the observed Set Image transfer model:

```text
timeout 3597
--speed-time 120
--speed-limit 102400
--insecure
```

Short helper commands that inspect or clean the target file also use EOS
`bash timeout 120 ...` so they are permitted through the CloudVision Command
API.

The action passes the CloudVision action user's access token to the device as
an `access_token` cookie for the file API request. Operators do not enter a
token, and logged command text redacts the cookie value.

## Idempotency

Operational messages use the structured envelope
`Step: <operation> | Status: <STARTED|SUCCESS|WARNING|ERROR|SKIPPED> | <detail>`.
Fresh transfers report `Artifact preload`, `Artifact transfer`, and either
`EOS image verification` (SWI), `EOS package verification` (SWIX, including
TerminAttr and extensions), or `Checksum verification` (RPM and other direct
files) lifecycle statuses. A transfer or verification error is sanitized and
logged before the action fails. An existing target that verifies is `SKIPPED`;
an existing target that must be replaced is `WARNING`, followed by `Existing
target cleanup` `STARTED`/`SUCCESS` or `ERROR` outcomes.

The download stream for SWI files is written through `/export/swi/swadapt`, so
the action does not assume the final on-flash file size or digest is identical
to the repository object. For `.swi` and `.swix` artifacts, including
TerminAttr and extensions, it checks whether the target filename already exists
and is non-empty, then uses EOS `verify flash:<path>` for both existing-target
idempotency and post-transfer verification. SWI verification is logged as
`EOS image verification`; SWIX verification is logged as `EOS package
verification`.

Successful post-transfer EOS verification is logged with the exact device
response after sanitization. A successful Command API completion may return
empty output; in that case the detail is `Device response: (none; absence of
Command API error confirms success).` EOS's interactive CLI may print `Verifying
... successful.` while the Command API response is empty; the action therefore
relies on completion without a structured Command API error and does not require
that response phrase. For RPM and other direct-downloaded files, if Software
Management exposes an MD5 or SHA512 digest, the generic checksum must match. If
digest metadata is unavailable, a successful full-file checksum readback is
treated as the verification signal.
An existing target that fails the verification probe is removed and rewritten.

A fresh SWI preload produces messages like:

```text
Step: Artifact preload | Status: STARTED | Artifact: EOS-4.34.7M.swi; Repository path: software/<uuid>/EOS-4.34.7M.swi; Destination: /mnt/flash/EOS-4.34.7M.swi
Step: Artifact transfer | Status: STARTED | Artifact: EOS-4.34.7M.swi; Source: https://<cvp>/api/v1/files/software/<uuid>/EOS-4.34.7M.swi; Destination: /mnt/flash/EOS-4.34.7M.swi; Device transfer command: <redacted command>
Step: Artifact transfer | Status: SUCCESS | Artifact: EOS-4.34.7M.swi; Source: https://<cvp>/api/v1/files/software/<uuid>/EOS-4.34.7M.swi; Destination: /mnt/flash/EOS-4.34.7M.swi; Detail: transfer command completed.
Step: EOS image verification | Status: STARTED | Artifact: EOS-4.34.7M.swi; Destination: /mnt/flash/EOS-4.34.7M.swi; Device verify command: verify flash:EOS-4.34.7M.swi
Step: EOS image verification | Status: SUCCESS | Artifact: EOS-4.34.7M.swi; Destination: /mnt/flash/EOS-4.34.7M.swi; Device response: (none; absence of Command API error confirms success).
Step: Artifact preload | Status: SUCCESS | Artifact: EOS-4.34.7M.swi; Repository path: software/<uuid>/EOS-4.34.7M.swi; Destination: /mnt/flash/EOS-4.34.7M.swi; Detail: artifact was transferred and verified.
```

For an already verified target, the idempotency path is concise and does not
emit the post-transfer verification lifecycle:

```text
Step: Artifact preload | Status: STARTED | Artifact: EOS-4.34.7M.swi; Repository path: software/<uuid>/EOS-4.34.7M.swi; Destination: /mnt/flash/EOS-4.34.7M.swi
Step: Artifact preload | Status: SKIPPED | Artifact: EOS-4.34.7M.swi; Repository path: software/<uuid>/EOS-4.34.7M.swi; Destination: /mnt/flash/EOS-4.34.7M.swi; Reason: target file already verifies
```

## Example

For the normal Studio-designed preload workflow, select the device and leave
the defaults:

```text
Source: designed
Repository Image: auto
Repository Streaming Agent: auto
Repository Extensions: auto
Authority: auto
VRF: auto
Source IP: auto
Destination: auto
Force: False
```

For an explicit repository preload with an external TerminAttr and two
extensions, provide the selectors as follows. Spaces around the extension
commas are ignored:

```text
Source: repository
Repository Image: EOS-4.34.7M.swi
Repository Streaming Agent: TerminAttr-1.40.10-1.swix
Repository Extensions: switchapp-1.15.1-1.10.swix, otheragent-2.0.swix
Authority: auto
VRF: auto
Source IP: auto
Destination: auto
Force: False
```

The rendered device transfer is logged in redacted form:

```text
<redacted command>
```

For TerminAttr or extension artifacts, the action uses the same authenticated
CloudVision file API curl model and writes the file directly to flash with
`--output /mnt/flash/<artifact filename>`.

## Development

Run the package tests and repository checks from the repository root:

```shell
python -m unittest tests.test_studio_image_preload
make lint
```

Build the installable package artifact with:

```shell
./build_packages.sh studio-image-preload-action-pack
```
