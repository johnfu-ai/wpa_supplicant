# WPA Supplicant — Research Fork (IEEE 802.1X-2020 Study)

This repository is a research-oriented fork/minor adaptation of the upstream
`wpa_supplicant` project from [w1.fi](https://w1.fi/wpa_supplicant/). The goal
is to support personal study and experimental development around modern
enterprise authentication, especially concepts related to IEEE 802.1X-2020.

GitHub: [johnfu-ai/wpa_supplicant](https://github.com/johnfu-ai/wpa_supplicant)
(formerly `wpa_supplicant-8021X-2020`).

## Project Status

- Default branch (`main`): research work on `wpa_supplicant-2.11`
- Purpose: study, prototyping, and security research
- Production readiness: not guaranteed
- Intended audience: developers, students, and researchers working on 802.1X,
  EAP, and WLAN security internals

## Branches

| Branch | Contents |
| --- | --- |
| `main` | Research fork based on wpa_supplicant 2.11 (IEEE 802.1X-2020 experiments) |
| `w1.fi/wpa_supplicant_2.12` | Official `wpa_supplicant-2.12.tar.gz` snapshot (wpa_supplicant tree only) |
| `w1.fi/hostap-2_12` | Official hostap Git branch `2_12` (full tree: hostapd + wpa_supplicant + `doc/`) |
| `w1.fi/hostap-main` | Official hostap Git `main` (`2.13-devel`) |
| `w1.fi/hostap-pending` | Official hostap Git `pending` |

Canonical upstream Git (not GitHub):

```bash
git clone https://git.w1.fi/hostap.git
```

Web UI: [git.w1.fi/cgit/hostap](https://git.w1.fi/cgit/hostap/)

Developer documentation is generated with Doxygen from `doc/` in the full
hostap tree (`doc/mainpage.doxygen`). The published HTML at
[w1.fi/wpa_supplicant/devel](https://w1.fi/wpa_supplicant/devel/index.html)
is an older generated snapshot (labeled 2.5). Rebuild with `cd doc && make html`
from a full hostap checkout.

## About wpa_supplicant

`wpa_supplicant` is a client-side supplicant implementation used on wireless
stations (and some wired deployments) to handle:

- WPA/WPA2/WPA3 and RSN authentication flows
- IEEE 802.1X/EAPOL state machines
- Roaming and key management with supported drivers
- Integration with CLI/GUI frontends such as `wpa_cli` and `wpa_gui`

It supports common EAP methods such as EAP-TLS, PEAP, TTLS, SIM/AKA families,
and others, depending on build-time configuration.

## Scope of This Fork

This repository focuses on learning and extension work, for example:

- Reviewing and understanding existing 802.1X/EAP state machine behavior
- Evaluating interoperability assumptions against IEEE 802.1X-2020 workflows
- Testing configuration combinations and feature toggles in controlled setups
- Building experimental changes before proposing any hardened implementation

## Build Quick Start (Linux)

From the repository root:

```bash
cd wpa_supplicant
cp defconfig .config
make -j"$(nproc)"
```

Build outputs typically include:

- `wpa_supplicant`
- `wpa_cli`

## Minimal Runtime Example

Create or adapt a configuration file:

```bash
cp wpa_supplicant/wpa_supplicant.conf /tmp/wpa_supplicant.conf
```

Run in foreground for debugging:

```bash
sudo ./wpa_supplicant/wpa_supplicant -i wlan0 -c /tmp/wpa_supplicant.conf -d
```

Run in background:

```bash
sudo ./wpa_supplicant/wpa_supplicant -i wlan0 -c /tmp/wpa_supplicant.conf -B
```

If multiple driver backends are enabled in `.config`, specify one explicitly:

```bash
sudo ./wpa_supplicant/wpa_supplicant -D nl80211 -i wlan0 -c /tmp/wpa_supplicant.conf -d
```

## IEEE 802.1X-2020 Extension Plan (Research)

Suggested phased plan for further development:

1. Baseline Mapping
   - Map current code paths for EAPOL, backend auth, and key handling.
   - Document where behavior aligns/diverges from your target interpretation of
     IEEE 802.1X-2020.
2. Controlled Feature Experiments
   - Add compile-time or runtime flags for experimental logic.
   - Keep behavior changes isolated and reversible.
3. Interoperability Testing
   - Validate against known RADIUS/EAP server setups and multiple client
     profiles.
   - Capture packet traces and regression notes for each experiment.
4. Hardening and Review
   - Remove temporary hooks and dead paths.
   - Add documentation and reproducible tests for accepted changes.

## Recommended Research Workflow

- Keep upstream documentation close:
  - `README`
  - `wpa_supplicant/README`
  - `wpa_supplicant/defconfig`
- Record test matrix details:
  - interface/driver (`nl80211`, etc.)
  - EAP method
  - certificate and trust model
  - expected vs observed result
- Prefer small, reviewable commits for each experimental hypothesis.

## Repository Notes

- Main source area: `wpa_supplicant/`
- Shared protocol/crypto/driver code: `src/`
- Build configuration template: `wpa_supplicant/defconfig`
- Runtime configuration sample: `wpa_supplicant/wpa_supplicant.conf`
- PAE unit tests: `tests/pae/` (`cd tests/pae && make test`)

## License and Attribution

This codebase is based on `wpa_supplicant`, which is distributed under the BSD
license (3-clause style, no advertising clause). Please retain original
copyright notices and follow upstream contribution/license requirements.

Upstream:
- Project page: https://w1.fi/wpa_supplicant/
- Git: https://git.w1.fi/hostap.git
- Refs: https://git.w1.fi/cgit/hostap/refs/

## Security, Compliance, and Ethics

- Use this repository only in authorized environments.
- Do not test against networks or systems without explicit permission.
- Experimental authentication changes can weaken security if misconfigured;
  validate carefully before any broader deployment.

## Disclaimer

This repository is an independent research effort and is not an official
release or endorsement from the upstream maintainers.
