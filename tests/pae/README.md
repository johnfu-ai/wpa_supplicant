# PAE Unit Tests

Unit tests for the PAE (Port Access Entity) components of the IEEE 802.1X-2020
implementation in wpa_supplicant.

## Directory Layout

```
tests/pae/
├── Makefile                      # Build all PAE unit tests
├── README.md                     # This file
└── test_ieee802_1x_logon.c       # Tests for the Logon Process state machine
```

Source under test lives in `src/pae/`:

```
src/pae/
├── ieee802_1x_logon.h            # Public API
└── ieee802_1x_logon.c            # Implementation (Clause 12 Logon Process)
```

## Build and Run

```bash
# From this directory:
make test

# Build only (no run):
make test_ieee802_1x_logon

# Clean build artifacts:
make clean
```

## Test Files

### `test_ieee802_1x_logon.c`

Verifies: #19 REQ-F-LOGON-001 — Logon Process state machine initialization  
See: IEEE 802.1X-2020, Clause 12

| Test ID              | Test function                                  | What it verifies                          |
|----------------------|------------------------------------------------|-------------------------------------------|
| TC-LOGON-INIT-001    | `test_logon_init_valid_ctx_returns_nonnull`    | init with valid ctx returns non-NULL      |
| TC-LOGON-INIT-002    | `test_logon_init_null_ctx_returns_null`        | init with NULL ctx returns NULL (guard)   |
| TC-LOGON-DEINIT-001  | `test_logon_deinit_null_is_safe`               | deinit(NULL) does not crash               |
| TC-LOGON-INIT-003    | `test_logon_init_initial_state_is_disconnected`| initial state is LOGON_DISCONNECTED       |
| TC-LOGON-INIT-004    | `test_logon_init_stores_ctx_pointer`           | stored ctx pointer equals the one at init |

## Adding New Tests

1. Create a new `test_ieee802_1x_<module>.c` in this directory, following the
   pattern in `test_ieee802_1x_logon.c`:
   - Include `utils/includes.h` first, then `utils/common.h`
   - Provide `os_zalloc` and `wpa_printf` stubs (see test file for examples)
   - Use the `TEST()` / `RUN()` / `ASSERT_*` macros for consistent output

2. Add a new build rule to `Makefile`:
   ```makefile
   test_ieee802_1x_<module>: test_ieee802_1x_<module>.c $(SRC_PAE)/ieee802_1x_<module>.c
       $(CC) $(CFLAGS) -o $@ $^
   ```

3. Add the target to the `test:` phony rule:
   ```makefile
   test: test_ieee802_1x_logon test_ieee802_1x_<module>
       ./test_ieee802_1x_logon
       ./test_ieee802_1x_<module>
   ```

4. Link to the GitHub issue that traces the requirement being verified.

## Traceability

All tests in this directory trace to GitHub Issues in the
`std_dev_practices-8021X-2020` repository:

- #19 REQ-F-LOGON-001 — Logon Process state machine (Clause 12)
- #20 REQ-F-LOGON-002 — NID selection (stub, Wave 1)
- #21 REQ-F-LOGON-003 — PACP authentication initiation
- #22 REQ-F-LOGON-004 — CP connectivity signalling
