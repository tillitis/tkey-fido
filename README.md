
[![ci](https://github.com/tillitis/tkey-gido/actions/workflows/ci.yaml/badge.svg?branch=main&event=push)](https://github.com/tillitis/tkey-fido/actions/workflows/ci.yaml)

# Tillitis TKey U2F/FIDO Support

WIP support for U2F/FIDO using the [Tillitis](https://tillitis.se/)
TKey USB security token.

Changes might be made to the fido device app, causing the identity to
change.

See [Release notes](docs/release_notes.md).

## Building

Use `build.sh` to clone dependencies and build with native tools.

See [Tillitis Developer Handbook](https://dev.tillitis.se/) for tool
support.

## fido application protocol

`fido` has a simple protocol on top of the [TKey Framing
Protocol](https://dev.tillitis.se/protocol/#framing-protocol) with the
following requests:

| *command*                  | *FP length* | *code* | *data*                                       | *response*               |
|----------------------------|-------------|--------|----------------------------------------------|--------------------------|
| `CMD_GET_NAMEVERSION`      | 1 B         | 0x01   | none                                         | `RSP_GET_NAMEVERSION`    |
| `APP_CMD_U2F_REGISTER`     | 128 B       | 0x03   | 32 B appli_param from Relying Party          | `RSP_U2F_REGISTER` * 2   |
| `CMD_U2F_CHECKONLY`        | 128 B       | 0x05   | 32 B appli_param, 64 B keyhandle             | `RSP_U2F_CHECKONLY`      |
| `CMD_U2F_AUTHENTICATE_SET` | 128 B       | 0x07   | 32 B appli_param, 32 B chall_param           | `RSP_U2F_AUTHENTICATE` 1 |
| `CMD_U2F_AUTHENTICATE_GO`  | 128 B       | 0x08   | 64 B keyhandle, 1 B check_user, 4 B counter, | `RSP_U2F_AUTHENTICATE` 2 |

All responses begin with a 1 byte Status Code:

| *status code* | *code* |
|---------------|--------|
| OK            | 0      |
| BAD           | 1      |

| *response*               | *FP length* | *code* | *data*                                      |
|--------------------------|-------------|--------|---------------------------------------------|
| `RSP_GET_NAMEVERSION`    | 32 B        | 0x02   | 1 B SC, 4 B name0, 4 B name1, 4 B version   |
| `RSP_U2F_REGISTER` 1     | 128 B       | 0x04   | 1 B SC, 1 B user_presence, 64 B keyhandle   |
| `RSP_U2F_REGISTER` 2     | 128 B       | 0x04   | 1 B SC, 64 B pubkey                         |
| `RSP_U2F_CHECKONLY`      | 4 B         | 0x06   | 1 B SC, 1 B bool (keyhandle OK?)            |
| `RSP_U2F_AUTHENTICATE` 1 | 128 B       | 0x09   | 1 B SC                                      |
| `RSP_U2F_AUTHENTICATE` 2 | 128 B       | 0x09   | 1 B SC, 1 B keyhandle_ok, 1 B user_presence |
| `RSP_UNKNOWN_CMD`        | 1 B         | 0xff   | none                                        |

It identifies itself with:

- `name0`: "tk1  "
- `name1`: "fido"

Please note that `fido` also replies with a `NOK` Framing Protocol
response status if the endpoint field in the FP header is meant for
the firmware (endpoint = `DST_FW`). This is recommended for
well-behaved device applications so the client side can probe for the
firmware.

Typical use by a client application:

1. Probe for firmware by sending firmware's `GET_NAME_VERSION` with FP
   header endpoint = `DST_FW`.
2. If firmware is found, load `fido` device app.
3. Upon receiving the device app digest back from firmware, switch to
   start talking the `fido` protocol above.
4. ...


**Please note**: The firmware detection mechanism is not by any means
secure. If in doubt a user should always remove the TKey and insert it
again before doing any operation.

## Licenses and SPDX tags

Unless otherwise noted, the project sources are licensed under the
terms and conditions of the "GNU General Public License v2.0 only":

> Copyright Tillitis AB.
>
> These programs are free software: you can redistribute it and/or
> modify it under the terms of the GNU General Public License as
> published by the Free Software Foundation, version 2 only.
>
> These programs are distributed in the hope that it will be useful,
> but WITHOUT ANY WARRANTY; without even the implied warranty of
> MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
> General Public License for more details.

> You should have received a copy of the GNU General Public License
> along with this program. If not, see:
>
> https://www.gnu.org/licenses

See [LICENSE](LICENSE) for the full GPLv2-only license text.

External source code we have imported are isolated in their own
directories. They may be released under other licenses. This is noted
with a similar `LICENSE` file in every directory containing imported
sources.

The project uses single-line references to Unique License Identifiers
as defined by the Linux Foundation's [SPDX project](https://spdx.org/)
on its own source files, but not necessarily imported files. The line
in each individual source file identifies the license applicable to
that file.

The current set of valid, predefined SPDX identifiers can be found on
the SPDX License List at:

https://spdx.org/licenses/

All contributors must adhere to the [Developer Certificate of Origin](dco.md).

