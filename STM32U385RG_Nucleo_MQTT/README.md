# STM32U385RG_Nucleo_MQTT

Bare-metal demo on the **NUCLEO-U385RG-Q** (STM32U385RG, Cortex-M33,
STM32U3 family — no TrustZone, 1 MB flash, 256 KB SRAM) showing
wolfCrypt, wolfSSL/TLS 1.3, wolfMQTT, FIPS 140-3 Ready, and wolfBoot
verified boot in a minimal-size profile.

## Features

- **wolfCrypt test + benchmark** on bare metal across four crypto profiles
- **TLS 1.3 client** with mutual authentication (ECDHE-ECDSA, P-384)
  - Cipher suite restricted to `TLS13_AES_128_GCM_SHA256`
  - Curve restricted to `secp384r1`
- **wolfMQTT over USART1** with a host-side UART-to-TCP bridge to a local
  wolfMQTT broker (mTLS required)
- **Console:** ARM semihosting (printf via OpenOCD); UART is reserved
  for MQTT/TLS bytes only
- **TRNG:** STM32 hardware RNG (`STM32_RNG`) enabled in every variant
- **FIPS 140-3 Ready:** wolfCrypt v7.0.0 module with pinned-section linker
  for stable in-core integrity hash
- **wolfBoot:** verified boot (ECC384 + SHA384) loaded at 0x08010000

## Build Variants (`CONFIG=`)

| Config | Description |
|--------|-------------|
| `c`    | Pure C single-precision math (`WOLFSSL_SP_C`) |
| `asm`  | Cortex-M Thumb2 ASM SP math (`WOLFSSL_SP_ARM_CORTEX_M_ASM`) |
| `hw`   | ASM + STM32 HW HASH + CRYP (AES) offload |
| `fips` | wolfCrypt FIPS 140-3 Ready module (validated software path only) |

TRNG (`STM32_RNG`) is on in all four. The FIPS variant deliberately uses
the validated software crypto path — the in-core integrity hash covers
that code, and STM32 HW HASH/AES is outside the FIPS boundary.

## Code Size

All builds: `arm-none-eabi-gcc 13.2`, `-Os -g3 -ffunction-sections
-fdata-sections -fomit-frame-pointer -mfloat-abi=soft`,
`-Wl,--gc-sections --specs=nano.specs --specs=rdimon.specs`. Math:
`WOLFSSL_SP_MATH` (small SP only, no general big-int). `NO_ERROR_STRINGS`
on. `data` is initialized in flash and copied to RAM at startup, so
`flash_used = text + data`. `bss` includes the linker's 16 KB stack
+ 4 KB heap reserve (actual zero-initialized data is ~6 KB). All
values in bytes.

### wolfCrypt test (`make test`)

| Variant | text | data | bss | flash used | Δ vs `c` |
|---------|----:|----:|----:|----:|----:|
| c    | 116,696 | 116 | 21,084 | 116,812 |  ref |
| asm  | 120,012 | 116 | 21,084 | 120,128 | +3,316 |
| hw   | 107,636 | 116 | 21,244 | 107,752 | -9,060 |
| fips | 159,692 | 120 | 21,208 | 159,812 | +43,000 |

### wolfCrypt benchmark (`make bench`)

| Variant | text | data | bss | flash used | Δ vs `c` |
|---------|----:|----:|----:|----:|----:|
| c    |  79,824 | 352 | 21,144 |  80,176 |  ref |
| asm  |  83,152 | 352 | 21,144 |  83,504 | +3,328 |
| hw   |  70,720 | 352 | 21,304 |  71,072 | -9,104 |
| fips | 122,764 | 356 | 21,260 | 123,120 | +42,944 |

### wolfMQTT + TLS 1.3 mTLS app (`make app`)

App variants (non-FIPS) are trimmed for TLS 1.3 client only with
AES-256-GCM-SHA384 and ECDSA-ECDHE P-384: no AES-128, no AES-CBC, no
SHA-224 (gated on `WOLFMQTT_DEMO && !HAVE_FIPS` in `user_settings.h`).
FIPS keeps the broader algorithm set required by its CAST KATs.

| Variant | text | data | bss | flash used | Δ vs `c` |
|---------|----:|----:|----:|----:|----:|
| c    | 129,920 | 148 | 25,340 | 130,068 |  ref |
| asm  | 133,236 | 148 | 25,340 | 133,384 | +3,316 |
| hw   | 124,924 | 148 | 25,508 | 125,072 | -4,996 |
| fips | 175,392 | 152 | 25,464 | 175,544 | +45,476 |

The full TLS 1.3 mTLS MQTT client fits in **~125–176 KB of flash**
(13–18% of 1 MB). The wolfBoot-linked variant (`make app WOLFBOOT=1`)
has identical sizes — the linker change only relocates vectors to
0x08010100, code is unchanged.

### Per-component breakdown of `app-hw` (125,072 bytes flash)

Source-attribution from `arm-none-eabi-nm --print-size --size-sort -l`,
filtered to `T/t/R/r/D/d` (text + rodata + data; flash-resident only).
% is of total flash (125,072).

| Component                         | Bytes  |   %   |
|-----------------------------------|-------:|------:|
| **wolfCrypt** (`wolfcrypt/src/`)  | 52,506 | 42.0% |
| **wolfSSL TLS** (`src/`)          | 34,703 | 27.7% |
| **STM32 HAL** (HAL_HASH, HAL_CRYP, HAL_UART, HAL_RCC, ...) | 12,949 | 10.4% |
| **newlib** (libc, nano)           | 12,779 | 10.2% |
| **wolfMQTT** (`mqtt_client.c`, `mqtt_packet.c`, `mqtt_socket.c`) | 5,572 |  4.5% |
| Demo glue (`main.c`, `hw_init.c`, `stubs.c`, `semihost.c`, `it.c`, MSP) | 1,422 | 1.1% |
| Embedded certs (CA + client cert + key, P-384 DER) | 1,239 | 1.0% |
| libgcc / libc-arch (memcpy/memmove/strcmp ASM) | 766 | 0.6% |
| UART transport (`uart_net.c` code) | 536 | 0.4% |
| CMSIS (startup + system_stm32u3xx.c) | 152 | 0.1% |
| **Total attributed**              | **122,624** | **98.0%** |

Remainder (~2.4 KB) is small symbols, vector table, interrupt stubs,
and section padding.

Application crypto (wolfCrypt + wolfSSL TLS + wolfMQTT) is **92.8 KB
(74% of flash)**. Standard-library glue (newlib + libgcc + arch) is
**13.5 KB (11%)**. wolfBoot itself is a separate 35 KB binary at
0x08000000.

Big size wins applied here:
- `WOLFSSL_SP_MATH` instead of `WOLFSSL_SP_MATH_ALL` drops generic
  big-int code (`sp_int.c`) in favor of curve-specific paths only.
- `NO_ERROR_STRINGS` removes the wolfCrypt error-string table.
- `--specs=nano.specs` (newlib-nano) drops `%f`/`%e`/`%g` printf,
  double-precision soft-float math, and `mprec.c`.
- `-mfloat-abi=soft` removes FPU register save/restore at ABI
  boundaries (small bump in newlib soft-float helpers).

See [BENCHMARKS.md](BENCHMARKS.md) for full breakdown including top
consumers within wolfCrypt and runtime numbers.

Re-generate the table at any time with `make size-report` after building.

## Quick Start

### Prerequisites

- `arm-none-eabi-gcc` (tested with 13.2)
- STM32Cube FW U3 pack at `~/STM32Cube/Repository/STM32Cube_FW_U3_V1.3.0`
- `wolfssl/`, `wolfmqtt/`, `wolfboot/` checkouts as siblings of this
  repo (or override via `WOLFSSL_ROOT=…`, etc.)
- OpenOCD with STM32U3 support (semihosting console)
- `STM32_Programmer_CLI` (st-flash does NOT support STM32U3 chipid `0x454`)
- Python 3 + `pyserial` (UART bridge)

### 1. wolfCrypt self-test

```bash
make test CONFIG=hw
make flash                          # uses STM32_Programmer_CLI
openocd -f interface/stlink.cfg -f target/stm32u3x.cfg \
  -c "init; arm semihosting enable; reset run"
```

Expect: `wolfcrypt_test()` prints "Test complete" with all sub-tests
PASS.

### 2. wolfCrypt benchmark

```bash
make bench CONFIG=hw
make flash
openocd -f interface/stlink.cfg -f target/stm32u3x.cfg \
  -c "init; arm semihosting enable; reset run"
```

Repeat for `CONFIG=c`, `CONFIG=asm` to compare runtimes.

### 3. wolfMQTT + TLS 1.3 mTLS over UART

```bash
# One-time: P-384 ECDSA CA + server + client certs
host/gen_test_certs.sh

# Build + flash
make app CONFIG=hw
make flash

# Three host terminals:
host/run_broker.sh                      # T1: wolfMQTT broker on :8883
python3 host/uart_bridge.py /dev/ttyACM0 localhost:8883   # T2: UART <-> TCP
openocd -f interface/stlink.cfg -f target/stm32u3x.cfg \
  -c "init; arm semihosting enable; reset run"            # T3: console

# T4: poke the device
mosquitto_pub --cafile certs/ca-cert.pem \
  --cert certs/client-cert.pem --key certs/client-key.pem \
  -p 8883 -t wolf/stm32u385/cmd -m "hello"
```

Expect TLS 1.3 handshake, MQTT CONNECT/SUBACK, and round-trip publish.

### 3a. mTLS with a DHUK-wrapped client key

`DHUK=1` replaces the buffer-loaded client key with one whose private scalar
only ever exists wrapped, unwrapped inside SAES for each signature:

```bash
make app CONFIG=hw DHUK=1                              # builds into build/app-hw-dhuk/
make flash CONFIG=hw DHUK=1 TARGET=app SN=<stlink-sn>  # same variant path
```

`DHUK=1` requires `CONFIG=hw`; the build stops with an error for any other
config. It builds to its own directory, so it never collides with the stock
`app-hw` objects; pass the same `DHUK=1 TARGET=app` to `make flash` or it will
flash a different variant. Run the host side exactly as above. The console adds one line per handshake:

```
[dhuk] client key provisioned (48-byte wrapped scalar)
[dhuk] CertificateVerify signed on the device (103-byte sig)
```

The wrapped blob is bound to the silicon that produced it, so a build flashed
to a different part will fail to sign. Note that the demo wraps the plaintext
client key from `certs_gen.h` at startup in place of a factory provisioning
step, so that scalar is present in flash and briefly in RAM; a product wraps it
off-device and ships only the blob and the seed.

Nothing in `dhuk_key.c` is family-specific: it uses only the portable wolfCrypt
DHUK device plus `wolfSSL_CTX_use_PrivateKey_Id()`, and does not use the U3 CCB.
The same file compiles and runs on any STM32 with SAES and PKA. The wrapped
scalar sign path is validated on STM32U385 (U3), STM32U585 and STM32U545 (U5)
for both P-256 and P-384; only this demo project's board scaffolding -- HAL
pack, clock and UART init, linker script -- is U385-specific.

`src/dhuk_key.c` explains how the key reaches TLS; the short version is that TLS
is handed a key *id* bound to a crypto-callback device, because
`wc_ecc_import_wrapped_private()` puts the blob on an `ecc_key` that TLS has no
way to accept directly.

### 4. wolfCrypt FIPS 140-3 Ready

```bash
# One-time: download FIPS Ready bundle and overlay latest stable
host/fips_fetch.sh

# First build prints the in-core integrity hash:
make test CONFIG=fips
make flash
openocd -f interface/stlink.cfg -f target/stm32u3x.cfg \
  -c "init; arm semihosting enable; reset run"
# -> "hash = <64-char hex>"
```

Copy the hash into `user_settings.h` (unquoted):

```c
#define WOLFCRYPT_FIPS_CORE_HASH_VALUE \
    DD9A790194F5FA352C85B000B3C7EF38E7ED55A5AA3A2EFD0528C8357448D4F3
```

Rebuild and re-flash:

```bash
make clean CONFIG=fips
make test CONFIG=fips
make flash
```

The FIPS-pinned linker script (`linker/stm32u385rg_fips.ld`) keeps the
`wolfcrypt_first.o … wolfcrypt_last.o` boundary contiguous so this hash
is **stable across rebuilds**. Bundle source:
`https://www.wolfssl.com/wolfssl-5.9.1-gplv3-fips-ready.zip`. The overlay
script applies the latest `v*-stable` tag while preserving FIPS-boundary
files (`fips.c`, `fips_test.c`, `wolfcrypt_first.c`, `wolfcrypt_last.c`).

### 5. wolfBoot verified boot

Requires the wolfBoot STM32U3 port (PR
[wolfSSL/wolfBoot#758](https://github.com/wolfSSL/wolfBoot/pull/758)).

```bash
make wb-build                       # build wolfBoot itself
make wb-keys                        # one-time ECC384 keypair
make wb-app CONFIG=hw               # app linked at 0x08010100
make wb-sign CONFIG=hw              # sign with ECC384 + SHA384
make wb-flash CONFIG=hw             # flash bootloader + signed app
```

The wolfBoot-linked app builds into `build/app-hw-wb/`, separate from the flat
`make app` output. Add `DHUK=1` to `wb-app`, `wb-sign` and `wb-flash` to build,
sign and flash the `build/app-hw-dhuk-wb/` variant instead.

## Flash Layout (wolfBoot)

```
0x08000000 ┌──────────────────────┐
           │  wolfBoot (64 KB)    │  Bank 1
0x08010000 ├──────────────────────┤
           │  BOOT partition      │
           │  (448 KB)            │  Bank 1
           │  [256 B hdr + app]   │
0x08080000 ├──────────────────────┤
           │  UPDATE partition    │
           │  (448 KB)            │  Bank 2
0x080F0000 ├──────────────────────┤
           │  SWAP (4 KB)         │  Bank 2
0x080F1000 ├──────────────────────┤
           │  (reserved)          │
0x080FFFFF └──────────────────────┘
```

- Sector size: 4 KB (dual-bank STM32U3)
- Signing: ECC384 + SHA384 (matches the TLS profile so the same code
  path is shared by app and bootloader)
- Image header: 256 B (`WB_APP_ADDR = 0x08010100`)
- No TrustZone (`TZEN=0`)

## Directory Layout

```
STM32U385RG_Nucleo_MQTT/
├── Makefile                       # all targets: test bench app flash wb-*
├── user_settings.h                # wolfSSL + wolfMQTT config (per-variant overlays in Makefile)
├── wolfmqtt_user_settings.h       # wolfMQTT-specific options
├── src/
│   ├── main.c                     # unified entry — gated by NO_CRYPT_TEST,
│   │                              # NO_CRYPT_BENCHMARK, WOLFMQTT_DEMO
│   ├── uart_net.{c,h}             # USART1 IRQ ring buffer + MqttNet callbacks
│   ├── hw_init.c                  # clocks (96 MHz), RNG, HASH, AES init
│   ├── semihost.c                 # ARM semihosting printf retarget
│   ├── stubs.c                    # _sbrk, time()
│   ├── certs.h / certs_gen.h      # embedded P-384 test certificates
│   └── (STM32 HAL template files)
├── linker/
│   ├── stm32u385rg_flat.ld        # standalone (no bootloader)
│   ├── stm32u385rg_fips.ld        # CONFIG=fips: pins wolfCrypt FIPS module
│   └── stm32u385rg_wb.ld          # WOLFBOOT=1: app vectors @ 0x08010100
├── host/
│   ├── gen_test_certs.sh          # generate P-384 ECDSA test certs
│   ├── run_broker.sh              # start wolfMQTT broker with mTLS
│   ├── uart_bridge.py             # serial <-> TCP bridge
│   └── fips_fetch.sh              # download FIPS Ready bundle + overlay latest stable
├── third_party/                   # FIPS Ready tree lives here (git-ignored)
└── README.md
```

## Make Variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `CONFIG` | `c` | Build variant: `c`, `asm`, `hw`, `fips` |
| `WOLFBOOT` | (unset) | Set to `1` to use wolfBoot linker (vectors at 0x08010100) |
| `WOLFSSL_ROOT` | `../../wolfssl` | wolfSSL source tree |
| `WOLFMQTT_ROOT` | `../../wolfmqtt` | wolfMQTT source tree |
| `WOLFBOOT_ROOT` | `../../wolfboot` | wolfBoot source tree |
| `STM32CUBE_FW_U3` | `~/STM32Cube/Repository/STM32Cube_FW_U3_V1.3.0` | ST HAL pack |
| `STM32_PROG` | `…/STM32_Programmer_CLI` | flasher path (override if installed elsewhere) |

## Tips

- The **`hw` variant** is the smallest because HASH and AES move to the
  peripheral, deleting the C/ASM implementations.
- The **`asm` variant** is fastest for ECDSA P-384 (Cortex-M-specific SP
  math) at a small size cost (~3 KB).
- The **`fips` variant** is largest (validated software crypto plus
  fips.c/fips_test.c) and needs a stable in-core integrity hash; the
  pinned linker keeps this hash reproducible across rebuilds.
- The benchmark binary is ~30% smaller than the test binary because it
  excludes the self-test vector suite.
- Use `make size-report` after building to compare all variants.
- Semihosting requires a debugger probe attached. Without one, `BKPT`
  instructions fault. For untethered operation, replace `semihost.c`
  with a UART or SWO/ITM logger.

## Troubleshooting

- **`st-flash`: chipid mismatch.** st-flash does not support STM32U3
  (chipid `0x454`). Use `STM32_Programmer_CLI` (already wired to
  `make flash`).
- **OpenOCD `flash erase` fails on bank 1.** The `stm32l4x` flash driver
  in OpenOCD's `stm32u3x.cfg` cannot reliably erase bank 1 — use
  `STM32_Programmer_CLI` for flashing and OpenOCD only for SWD/halt
  /resume/semihosting.
- **FIPS in-core integrity check fails.** The hash in `user_settings.h`
  must match the build. After any change that touches the FIPS module
  (compiler flags, FIPS source set, optimization), re-capture: flash,
  read `hash = …` from semihosting, paste back, rebuild, re-flash.
- **No semihosting output.** OpenOCD must connect with
  `arm semihosting enable` after `init`. The semihosting `BKPT` is
  emitted before any reads, so the printf landed before OpenOCD looked.
  `reset run` after `arm semihosting enable` ensures stdout is captured.
