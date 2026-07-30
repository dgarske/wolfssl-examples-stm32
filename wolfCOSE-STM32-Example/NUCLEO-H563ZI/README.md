# wolfCOSE Example - NUCLEO-H563ZI

Pre-configured STM32CubeMX project for wolfCOSE on NUCLEO-H563ZI. Verified on real hardware.

## Usage

1. Install the wolfSSL and wolfCOSE packs (see parent directory README)
2. Open `NUCLEO-H563ZI-wolfCOSE.ioc` in STM32CubeMX (already configured, do not create your own)
3. Generate code (Project -> Generate Code)
4. Apply the software-crypto conf edit and add the main.c glue (seed, printf, fflush) from the parent README
5. Build: `make GCC_PATH=/path/to/STM32CubeIDE/.../gnu-tools-for-stm32/tools/bin`
6. Flash and open the ST-LINK VCP at 115200 baud

## Expected Output

```
== wolfCOSE NUCLEO-H563ZI ==
Running wolfCOSE test (COSE_Sign1 ES256)...
wolfCOSE test: PASS (COSE_Sign1 99 bytes)
```

A real COSE_Sign1 ES256 message signed and verified on the Cortex-M33 (software SP-math ECC, TRNG entropy).

## What's Pre-Configured

- USART3: ST-LINK VCP, Asynchronous at 115200 baud (printf output)
- RNG: true random number generator enabled (signing entropy)
- TrustZone: disabled (non-secure, boots at 0x08000000)
- Software Packs: wolfSSL wolfCrypt Core, wolfCOSE Core and Test components
