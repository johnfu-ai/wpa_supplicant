# AGENTS.md — wpa_supplicant IEEE 802.1X-2020 Implementation

> **Purpose**: Authoritative context file for AI coding agents starting a new session on the wpa_supplicant codebase.  
> Read this file before any analysis, code generation, or debugging task.

---

## Project Mission

Extend **wpa_supplicant 2.12** to achieve full compliance with **IEEE Std 802.1X-2020** (Port-Based Network Access Control).

**Hard constraints**:
- Language: **C only** (no C++)
- Build system: **wpa_supplicant Makefile** (`wpa_supplicant/Makefile`)
- Output: compilable and runnable `wpa_supplicant` and `wpa_cli` binaries
- No new external dependencies beyond what wpa_supplicant already uses

---

## Workspace Layout

```
<workspace-root>/
├── wpa_supplicant/                 # ← YOU ARE HERE (research fork, base 2.12)
├── 8021X-2020.md/                  # IEEE 802.1X-2020 standard (Markdown study copy)
├── 8021X-2020.YANG/                # IEEE 802.1X-2020 YANG data models (normative)
└── 802.1X_dev_practices/           # Dev methodology, lifecycle, AI agents
    └── AGENTS.md                   # Full project context (read this too)
```

---

## Codebase Map

```
wpa_supplicant/
├── wpa_supplicant/               # Application layer
│   ├── wpa_supplicant.c          # Main supplicant logic, init, event loop
│   ├── wpa_supplicant_i.h        # Internal supplicant context (struct wpa_supplicant)
│   ├── wpas_kay.c / wpas_kay.h   # KaY integration bridge (wpa_supplicant ↔ MKA)
│   ├── eapol_test.c              # Standalone EAPOL test tool
│   ├── defconfig                 # Build feature flags template
│   └── wpa_supplicant.conf       # Runtime config example
└── src/
    ├── eapol_supp/               # Supplicant EAPOL state machine
    │   └── eapol_supp_sm.c/h     # IEEE 802.1X Clause 8 — Supplicant PAE
    ├── eap_peer/                 # EAP peer implementation
    │   ├── eap.c/h               # EAP state machine
    │   ├── eap_tls.c             # EAP-TLS
    │   ├── eap_peap.c            # EAP-PEAP
    │   ├── eap_teap.c            # EAP-TEAP (RFC 7170)
    │   └── eap_methods.c/h       # EAP method registry
    ├── eap_common/               # Shared EAP code (peer + server)
    ├── pae/                      # PAE / MACsec / MKA
    │   ├── ieee802_1x_kay.c/h    # MKA — IEEE 802.1X-2020 Clause 9
    │   ├── ieee802_1x_kay_i.h    # MKA internal types
    │   ├── ieee802_1x_cp.c/h     # Controlled Port state machine
    │   ├── ieee802_1x_key.c/h    # Key derivation
    │   ├── ieee802_1x_secy_ops.c/h  # SecY hardware abstraction
    │   ├── ieee802_1x_logon.c    # Logon Process SM — Clause 12
    │   ├── ieee802_1x_logon.h    # Logon Process public API + ieee802_1x_logon_ctx DI struct
    │   └── ieee802_1x_ancp.c/h   # ANCP — Clause 10/11.12 announced connectivity
    ├── eapol_auth/               # Authenticator EAPOL state machine
    ├── crypto/                   # Cryptographic primitives
    ├── tls/                      # TLS (internal or OpenSSL wrapper)
    ├── l2_packet/                # Layer-2 send/receive abstraction
    │   ├── l2_packet_linux.c     # Linux raw socket implementation
    │   └── l2_packet.h           # Interface (always use this, never l2_packet_linux.c directly)
    ├── rsn_supp/                 # RSN / WPA key management
    ├── ap/                       # AP mode support
    └── utils/                    # Common utilities
        ├── os.h / os_unix.c      # OS abstraction (use instead of libc directly)
        ├── common.h              # wpa_printf, wpa_hexdump, BIT(), etc.
        ├── list.h                # Doubly-linked list (dl_list_*)
        └── wpa_debug.h           # Debug logging levels
```

### Unit Test Directory (new)

```
tests/
└── pae/
    ├── Makefile                  # make test — builds and runs all PAE unit tests
    ├── README.md                 # Test directory docs
    └── test_ieee802_1x_logon.c   # TC-LOGON-INIT-001..004, TC-LOGON-DEINIT-001
```

Build and run PAE unit tests without hardware:
```bash
cd tests/pae && make test
```

---

## Build System

```bash
# Configure build
cd wpa_supplicant/wpa_supplicant
cp defconfig .config
# Edit .config — see relevant flags below
make -j$(nproc)

# Run supplicant (debug mode)
sudo ./wpa_supplicant -D nl80211 -i wlan0 -c wpa_supplicant.conf -d

# Run EAPOL test (no hardware needed)
./eapol_test -c test.conf -a 127.0.0.1 -s testing123
```

### Key Build Flags for IEEE 802.1X-2020

```makefile
CONFIG_IEEE8021X_EAPOL=y    # Core 802.1X supplicant (Clause 8)
CONFIG_MACSEC=y              # MACsec / IEEE 802.1AE + MKA/KaY (Clause 9)
CONFIG_IEEE8021X_2020_LOGON=y # Fork: Logon Process SM (Clause 12)
CONFIG_EAP_TLS=y             # EAP-TLS
CONFIG_EAP_PEAP=y            # EAP-PEAP
CONFIG_EAP_TTLS=y            # EAP-TTLS
CONFIG_EAP_TEAP=y            # EAP-TEAP (required for 802.1X-2020)
CONFIG_TLS=openssl           # TLS backend (openssl/gnutls/wolfssl)
CONFIG_LIBNL32=y             # Linux netlink (for nl80211 driver)
```

### Adding a New Source File

```makefile
# In src/pae/Makefile — add to LIB_OBJS
LIB_OBJS += ieee802_1x_logon.o

# In wpa_supplicant/Makefile — guard with CONFIG flag
ifdef CONFIG_IEEE8021X_2020_LOGON
OBJS += ../src/pae/ieee802_1x_logon.o
CFLAGS += -DCONFIG_IEEE8021X_2020_LOGON
endif
```

---

## IEEE 802.1X-2020 Key Concepts

### State Machines to Implement/Extend

| State Machine | Standard Reference | Current File | Status |
|---|---|---|---|
| Supplicant PAE | Clause 8.3 | `eapol_supp/eapol_supp_sm.c` | Partial (2010 base) + PACP logon_if callbacks |
| Authenticator PAE | Clause 8.4 | `eapol_auth/` | Partial |
| MKA (KaY) | Clause 9 | `pae/ieee802_1x_kay.c` | 2010 base + 2020 extensions (suspend/resume, group CAK) |
| Controlled Port (CP) | Clause 10/12.2 | `pae/ieee802_1x_cp.c` | Updated; SECURED transition wired to Logon Process |
| Logon Process | Clause 12 | `pae/ieee802_1x_logon.c` | Implemented (24 unit tests) |
| NID management | Clause 12.5 | `pae/ieee802_1x_logon.c` | Implemented (20 unit tests) |
| ANCP | Clause 10/11.12 | `pae/ieee802_1x_ancp.c` | Implemented (17 unit tests) |

### Remaining 802.1X-2020 Work

Waves 1-3 are implemented with unit evidence (90/90 tests, see
`802.1X_dev_practices` Phase 05/07). Still open:

1. **End-to-end functional verification** — eapol_test/RADIUS runs against a
   real authenticator (see Phase 07 outstanding items)
2. **Authenticator PAE (Clause 8.4) 2020 alignment** — supplicant side prioritized
3. **Formal coverage measurement** — no % tool configured yet
4. **Upstream sync follow-ups** — 2.12's EAP-over-auth-frame infra not yet
   integrated with the 2020 Logon flow

### YANG Data Model Reference

Use `8021X-2020.YANG/` to understand normative data structures:
- `ieee802-dot1x.yang` — management interface data model
- `ieee802-dot1x-types.yang` — type definitions: `pae-nid`, `pae-session-id`, etc.
- `ieee802-dot1x-eapol.yang` — EAPOL statistics

---

## Coding Standards

### Utilities: Always Use wpa_supplicant Abstractions

```c
/* Memory */
os_malloc(size)          /* instead of malloc() */
os_zalloc(size)          /* zero-filled malloc */
os_free(ptr)             /* instead of free() */
os_memcpy(dst, src, n)   /* instead of memcpy() */
os_memset(ptr, c, n)     /* instead of memset() */
os_strdup(str)           /* instead of strdup() */

/* Debug logging */
wpa_printf(MSG_DEBUG, "ieee802_1x_kay: %s", msg);
wpa_printf(MSG_ERROR, "ieee802_1x_cp: failed to allocate");
wpa_hexdump(MSG_MSGDUMP, "EAPOL frame", buf, len);

/* Lists */
struct dl_list list;
dl_list_init(&list);
dl_list_add(&list, &entry->list);
dl_list_del(&entry->list);
dl_list_for_each(entry, &list, struct my_type, list) { ... }
```

### Protocol State Machine Pattern (existing style)

```c
/* State machine step function — called by event loop */
void ieee802_1x_xxx_sm_step(struct ieee802_1x_xxx_sm *sm)
{
    /* Evaluate guards, transition state */
    /* Per IEEE 802.1X-2020 Clause X.Y */
}

/* External event triggers */
void ieee802_1x_xxx_event_name(struct ieee802_1x_xxx_sm *sm);
```

### Function Documentation

```c
/**
 * ieee802_1x_logon_init - Initialize the Logon Process state machine
 * @ctx: Dependency-injection context (ieee802_1x_logon_ctx) with all
 *       inter-SM callbacks populated. Must not be NULL.
 *
 * Initializes the IEEE 802.1X-2020 Logon Process per Clause 12.
 * Returns: Pointer to state machine, or NULL on failure
 *
 * Note: Implements IEEE 802.1X-2020 Clause 12 — Logon Process.
 * This implementation is based on understanding of the specification.
 * No copyrighted content from the standard is reproduced.
 */
struct ieee802_1x_logon *ieee802_1x_logon_init(struct ieee802_1x_logon_ctx *ctx);
```

### Comment Style for Standard References

```c
/* IEEE 802.1X-2020 Clause 8.3.2 — Supplicant PAE state HELD */
/* Per IEEE 802.1X-2020 Table 8-3 — Supplicant PAE variables */
/* IEEE 802.1X-2020 Section 9.4 — MKA timer values */
```

### What NOT to Do

```c
/* ❌ No OS-specific includes directly */
#include <linux/if_packet.h>   /* use l2_packet.h instead */
#include <sys/socket.h>        /* use l2_packet.h instead */

/* ❌ No standard text reproduction */
/* The MKA Hello Time is defined in Table 9-1 as... [quoted text] */  /* WRONG */

/* ❌ No C++ */
// No classes, templates, references, new/delete

/* ❌ No global state for protocol operations */
static struct ieee802_1x_kay *global_kay;  /* WRONG — pass as parameter */
```

---

## Development Workflow

### Before Writing Any Code

1. Read the relevant 802.1X-2020 clause in `../8021X-2020.md/8021X-2020.md`
2. Check the YANG model in `../8021X-2020.YANG/` for data model
3. Read existing related code in `src/pae/` or `src/eapol_supp/`
4. Create a GitHub Issue documenting what you're implementing
5. Write a failing test first (TDD Red)

### Test Strategy for C Code

Use existing test infrastructure:
- `wpa_supplicant/eapol_test` — EAPOL functional testing
- `src/utils/` unit tests — utility function tests
- `tests/pae/` — standalone PAE unit tests (no hardware, no RADIUS needed); run with `make test`
- Mock using function pointer injection (see `ieee802_1x_secy_ops.h` pattern and `ieee802_1x_logon_ctx`)

```c
/* Mock injection pattern — existing wpa_supplicant style */
struct ieee802_1x_kay_ctx {
    void *ctx;
    int (*get_macsec_capability)(void *ctx, enum macsec_cap *cap);
    int (*enable_protect_frames)(void *ctx, bool enabled);
    /* ... */
};
```

### Commit Message Format

```
feat(pae): implement Logon Process NID selection per Clause 12

Implements IEEE 802.1X-2020 Clause 12 Logon Process state machine.
Adds NID-aware network selection before EAPOL authentication.

Implements: #REQ-F-PAE-012
See: IEEE 802.1X-2020, Clause 12
```

### PR Checklist

- [ ] All existing `make` targets still compile
- [ ] New feature guarded with `#ifdef CONFIG_xxx` flag
- [ ] `defconfig` comment added for new flag
- [ ] IEEE 802.1X-2020 clause reference in all new functions
- [ ] No reproduction of copyrighted standard text
- [ ] Linked to GitHub issue with `Implements #N`

---

## Traceability

Code must reference GitHub Issues from the `802.1X_dev_practices` repo:

```c
/*
 * Implements: #REQ-F-PAE-012 (REQ-F: Logon Process NID selection)
 * Verifies:   #TEST-PAE-012
 * See:        IEEE 802.1X-2020, Clause 12
 */
```

---

## Copyright Compliance

`../8021X-2020.md/8021X-2020.md` is a **study reference only**. IEEE holds copyright.

- **NEVER** copy specification text into source files, headers, or comments
- **ALWAYS** reference by clause/section number only
- **PERMITTED**: protocol constants, field sizes, timer values

---

## Quick Commands

```bash
# Full build
cd wpa_supplicant && make -j$(nproc)

# Check for compile errors only (fast)
make -j$(nproc) 2>&1 | grep -E "error:|warning:"

# Run PAE unit tests (no hardware needed)
cd tests/pae && make test

# Run EAPOL test
cd wpa_supplicant && ./eapol_test -c test.conf -a 127.0.0.1 -p 1812 -s testing123

# Check what 802.1X features are enabled
grep -E "^CONFIG_(IEEE8021X|MACSEC|MOKO|EAP)" .config

# Find all Logon Process / MKA / KaY related code
grep -rn "ieee802_1x_logon\|ieee802_1x_kay\|ieee802_1x_cp" src/ tests/
```
