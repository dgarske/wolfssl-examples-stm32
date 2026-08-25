# NUCLEO-V873XJ (STM32V873XJ): Cortex-M85 (Armv8.1-M + Helium), 4 MB flash.
# Per STM32CubeProgrammer 2.22.0's SVD/STM32V873.svd: CRYP (fat, AES-192 +
# GCM/CCM) + SAES (DHUK/BHK) + HASH (new-gen) + PKA (V2, sign and verify) +
# RNG + CCB, all on RCC_AHB3ENR bits 0/1/2/3/8/15 -- an N6-shaped topology.
#
# No TZEN option byte: both flash-bank watermarks are secure and BOOTADD is
# 0x18000000, so it always boots Secure and everything is linked through the
# secure aliases (flash 0x18000000, AXI SRAM 0x34000000, peripherals
# +0x10000000). HW RNG/HASH/SAES/PKA are enabled and validated on silicon.

# ST publishes no stm32v8xx_dfp, so the device header is generated locally --
# see the guard below. Override the location with STM32V8_DFP=...
STM32V8_DFP ?= $(HOME)/Projects/STM/STM32V8/stm32v8xx_dfp
CUBE_DIR    := $(STM32V8_DFP)
CMSIS_DEVICE ?= $(CUBE_DIR)/Include

# Cortex-M85 CMSIS-Core, borrowed from the installed CMSIS 6.3.0 pack (the N6
# Cube FW pack carries an identical core_cm85.h).
CMSIS_CORE ?= $(HOME)/.local/share/stm32cube/packs/STMicroelectronics/CMSIS/6.3.0/CMSIS/Core/Include

# wolfcrypt_test can freeze in ed25519 (no fault, debug port dead) in a way
# that toggles with ANY code-placement change: -O1 vs -O2, -mtune, inserted
# printfs, or enabling unrelated features. -mtune=cortex-m33 helped one
# specific config but is NOT a reliable fix. Mechanism open; prime suspect
# is the flash fetch path (boot-ROM wait-states, uncached execution) or a
# silicon erratum. Next: run from SRAM (ST's RAM.ld) to isolate. Keep the
# tune flag meanwhile -- harmless and it stabilized several configs.
b_extra_defs += -mtune=cortex-m33

b_chip    := v873
b_core    := m85
b_chipdef := STM32V873xx
b_serial  := 002000303434511734313937

# C-file startup (no .s), same arrangement as c5a3/c562.
STARTUP_S   :=
BOARD_C_SRC := boards/v8/startup_stm32v873xx.c boards/v8/hw_init.c

# ST publishes no stm32v8xx_dfp, so the CMSIS device header is generated
# locally from the SVD that ships with STM32CubeProgrammer 2.22.0:
#
#   ./boards/v8/tools/svd2cmsis.py \
#       --svd ~/STMicroelectronics/STM32Cube/STM32CubeProgrammer/SVD/STM32V873.svd \
#       --out $(STM32V8_DFP)/Include
#
# The generated header is ST-derived and is deliberately NOT checked in --
# treat it like a vendor DFP. Only the generator (our code) is in the tree.
ifeq ($(wildcard $(CMSIS_DEVICE)/stm32v8xx.h),)
  $(error BOARD=v8 needs the CMSIS device header at $(CMSIS_DEVICE). \
          Generate it with boards/v8/tools/svd2cmsis.py -- see the comment \
          in boards/v8/board.mk. Override the location with STM32V8_DFP=)
endif
ifeq ($(wildcard $(CMSIS_CORE)/core_cm85.h),)
  $(error BOARD=v8 needs core_cm85.h at $(CMSIS_CORE) (CMSIS 6.x pack). \
          Override the location with CMSIS_CORE=)
endif

# OpenOCD has no stm32v8x.cfg, and only CubeProgrammer 2.22.0+ knows device
# ID 0x499. NOTE: ~/.local/bin/STM32_Programmer_CLI is a symlink to the
# CubeIDE 2.0.0 bundle (2.21.0) which does NOT know this part -- point at
# the standalone install explicitly.
# The Makefile's CUBE_PROGRAMMER default already points at the standalone
# install and its flash rule already uses mode=UR -- which this part
# requires, since mode=HOTPLUG fails against the running secure firmware
# with "Unable to get core ID". So no override is needed here.
USE_CUBE_PROGRAMMER := 1

# BUILD=cubemx is not wired yet (V8 ships new-generation HAL like C5, and
# no pack exists publicly). Leaving HAL_FAMILY empty makes the harness
# reject BUILD=cubemx with its normal guard rather than failing obscurely.
HAL_FAMILY :=
