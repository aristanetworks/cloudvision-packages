# Studio Image Preload Action Pack

This package adds the `Studio Image Preload` change-control action. The action
preloads an EOS SWI from CloudVision Software Management onto the selected
device and stops there. It does not set boot variables, schedule a reload, call
Set Image, or perform an upgrade.

The transfer uses the modern CloudVision file API:

```text
https://<cvp>/api/v1/files/software/<uuid>/<filename>
```

It intentionally does not use the legacy
`/cvpservice/image/getImagebyId/` endpoint.

## Source Modes

`designed` is the default. It resolves the Software Management image assigned
to the device, matching the image CloudVision Set Image is expected to use for
that device.

`running` resolves the device's currently reported running EOS version from
CloudVision inventory, then matches that version to a Software Management
repository artifact.

`repository` resolves the operator-provided `Repository Image` value against
the Software Management repository. Use a human-friendly image filename or
version, for example `EOS-4.34.7M.swi` or `4.34.7M`. Do not provide raw
file-server paths.

## Defaults

Leave `authority` empty to use the CloudVision authority from the action
runtime context. Set it only if the selected authority is not reachable from the
switch management network.

`VRF` defaults to `MGMT`, producing the Linux namespace `ns-MGMT`.

`Source IP` defaults to the selected device IP from CloudVision, matching the
management source address used for device interaction.

`Destination` defaults to `/mnt/flash/<artifact filename>`.

The curl guardrails match the observed Set Image transfer model:

```text
timeout 3597
--speed-time 120
--speed-limit 102400
--insecure
```

The action passes the CloudVision action user's access token to the device as
an `access_token` cookie for the file API request. Operators do not enter a
token, and logged command text redacts the cookie value.

## Example

For the normal Studio-designed preload workflow, select the device and leave
the defaults:

```text
Source: designed
VRF: MGMT
Source IP: <empty>
Destination: <empty>
Force: False
```

The rendered device transfer is equivalent to:

```text
bash timeout 3597 sudo ip netns exec ns-MGMT curl \
  https://<cvp>/api/v1/files/software/<uuid>/EOS-4.34.7M.swi \
  --insecure \
  --cookie "access_token=<redacted>" \
  --fail \
  --speed-time 120 \
  --speed-limit 102400 \
  -sS \
  --interface <device-management-ip> \
| /export/swi/swadapt /mnt/flash/EOS-4.34.7M.swi
```
