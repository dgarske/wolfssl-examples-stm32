# ---------------------------------------------------------------------------
# STM32U385RG demo — wolfCrypt test / bench / TLS+MQTT / FIPS / wolfBoot
#
# Usage:
#   make CONFIG=c    test       # wolfCrypt test, pure C
#   make CONFIG=asm  test       # wolfCrypt test, Thumb2 SP math ASM
#   make CONFIG=hw   test       # wolfCrypt test, STM32 HW HASH/AES
#   make CONFIG=hw   bench      # wolfCrypt benchmark (phase 2)
#   make CONFIG=hw   app        # wolfMQTT over UART (phase 3)
#   make CONFIG=fips test       # FIPS 140-3 Ready (phase 4)
#   make size-report            # aggregate size across all built configs
#   make flash                  # STM32_Programmer_CLI write build/$(TARGET)-$(CONFIG)/app.bin
#
# Make/env variables (override on command line if your siblings live elsewhere):
#   WOLFSSL_ROOT    = ../../wolfssl       (wolfSSL source tree)
#   WOLFMQTT_ROOT   = ../../wolfmqtt      (phase 3+)
#   WOLFBOOT_ROOT   = ../../wolfboot      (phase 5)
#   STM32CUBE_FW_U3 = $(HOME)/STM32Cube/Repository/STM32Cube_FW_U3_V1.3.0
# ---------------------------------------------------------------------------

# ----- Toolchain -----------------------------------------------------------
CROSS        ?= arm-none-eabi-
CC            = $(CROSS)gcc
AS            = $(CROSS)gcc -x assembler-with-cpp
OBJCOPY       = $(CROSS)objcopy
SIZE          = $(CROSS)size
NM            = $(CROSS)nm
OBJDUMP       = $(CROSS)objdump

# ----- Repos / paths -------------------------------------------------------
TOP          := $(abspath .)
# Repo layout: .../GitHub/wolfssl-examples-stm32/STM32U385RG_Nucleo_MQTT/
# Siblings live at .../GitHub/<repo> — 2 levels up from $(TOP).
REPO_SIBLING := $(abspath $(TOP)/../..)

WOLFSSL_ROOT    ?= $(REPO_SIBLING)/wolfssl
WOLFMQTT_ROOT   ?= $(REPO_SIBLING)/wolfmqtt
WOLFBOOT_ROOT   ?= $(REPO_SIBLING)/wolfboot
STM32CUBE_FW_U3 ?= $(HOME)/STM32Cube/Repository/STM32Cube_FW_U3_V1.3.0

# ----- Target / build config ----------------------------------------------
TARGET   ?= test
CONFIG   ?= c

ifeq ($(filter $(TARGET),test bench app),)
  $(error TARGET must be one of: test | bench | app)
endif
ifeq ($(filter $(CONFIG),c asm hw fips),)
  $(error CONFIG must be one of: c | asm | hw | fips)
endif

DHUK_SUFFIX := $(if $(filter 1,$(DHUK)),-dhuk)
WB_SUFFIX := $(if $(WOLFBOOT),-wb)
BUILD_DIR := $(TOP)/build/$(TARGET)-$(CONFIG)$(if $(filter app,$(TARGET)),$(DHUK_SUFFIX))$(WB_SUFFIX)

# ----- MCU / arch flags ----------------------------------------------------
MCU_FLAGS := -mcpu=cortex-m33 -mthumb -mfloat-abi=soft -mcmse
CPU_DEFS  := -DSTM32U385xx -DUSE_HAL_DRIVER

# ----- Variant overlays ---------------------------------------------------
VARIANT_DEFS :=
ifeq ($(CONFIG),c)
  VARIANT_DEFS += -DBUILD_CONFIG_NAME=\"c\"
endif
ifeq ($(CONFIG),asm)
  VARIANT_DEFS += -DBUILD_CONFIG_NAME=\"asm\" \
                  -DWOLFSSL_SP_ASM -DWOLFSSL_SP_ARM_CORTEX_M_ASM
endif
ifeq ($(CONFIG),hw)
  VARIANT_DEFS += -DBUILD_CONFIG_NAME=\"hw\" \
                  -DWOLFSSL_SP_ASM -DWOLFSSL_SP_ARM_CORTEX_M_ASM \
                  -DWOLFSSL_STM32_HASH -DWOLFSSL_STM32_AES
endif
ifeq ($(CONFIG),fips)
  # FIPS 140-3 Ready: uses the FIPS tree in third_party/wolfssl-fips-ready/
  # Run `host/fips_fetch.sh` first to populate it.
  FIPS_WOLFSSL_ROOT := $(TOP)/third_party/wolfssl-fips-ready
  ifeq ($(wildcard $(FIPS_WOLFSSL_ROOT)/wolfssl/wolfcrypt/settings.h),)
    $(error FIPS tree not found at $(FIPS_WOLFSSL_ROOT) — run host/fips_fetch.sh first)
  endif
  # Override WOLFSSL_ROOT to point at the FIPS tree
  WOLFSSL_ROOT := $(FIPS_WOLFSSL_ROOT)
  # FIPS uses validated software crypto only — no STM32 HW HASH/AES,
  # otherwise the FIPS-boundary symbols (e.g. wc_Sha256FinalRaw) aren't
  # compiled and the integrity-pinned linker fails to resolve them.
  VARIANT_DEFS += -DBUILD_CONFIG_NAME=\"fips\" \
                  -DWOLFSSL_SP_ASM -DWOLFSSL_SP_ARM_CORTEX_M_ASM \
                  -DHAVE_FIPS -DHAVE_FIPS_VERSION=7 \
                  -DHAVE_FIPS_VERSION_MAJOR=7 -DHAVE_FIPS_VERSION_MINOR=0 \
                  -DHAVE_FIPS_VERSION_PATCH=0
endif

# ----- Include paths ------------------------------------------------------
INCLUDES := \
  -I$(TOP) \
  -I$(TOP)/src \
  -I$(STM32CUBE_FW_U3)/Drivers/CMSIS/Core/Include \
  -I$(STM32CUBE_FW_U3)/Drivers/CMSIS/Device/ST/STM32U3xx/Include \
  -I$(STM32CUBE_FW_U3)/Drivers/STM32U3xx_HAL_Driver/Inc \
  -I$(WOLFSSL_ROOT) \
  -I$(WOLFSSL_ROOT)/wolfssl

# ----- Preprocessor / compile flags ---------------------------------------
COMMON_DEFS := -DWOLFSSL_USER_SETTINGS $(CPU_DEFS) $(VARIANT_DEFS)

CFLAGS    = $(MCU_FLAGS) $(INCLUDES) $(COMMON_DEFS) \
            -Os -g3 -ffunction-sections -fdata-sections \
            -fomit-frame-pointer \
            -Wall -Wno-unused-function -Wno-unused-variable \
            -fno-common -fno-strict-aliasing \
            -MMD -MP -std=gnu11

ASFLAGS  := $(MCU_FLAGS) -c -g3

# Select linker script:
#   WOLFBOOT=1   -> wolfBoot-offset layout (vectors @ 0x08010100)
#   CONFIG=fips  -> FIPS layout pinning the wolfCrypt module boundary
#   else         -> flat layout
ifdef WOLFBOOT
LDSCRIPT := $(TOP)/linker/stm32u385rg_wb.ld
else ifeq ($(CONFIG),fips)
LDSCRIPT := $(TOP)/linker/stm32u385rg_fips.ld
else
LDSCRIPT := $(TOP)/linker/stm32u385rg_flat.ld
endif
LDFLAGS  := $(MCU_FLAGS) \
            -T$(LDSCRIPT) \
            --specs=nano.specs --specs=rdimon.specs \
            -u _printf_float \
            -Wl,--gc-sections \
            -Wl,-Map=$(BUILD_DIR)/app.map \
            -Wl,--print-memory-usage

LDLIBS   := -lrdimon -lc -lm

# ----- Sources ------------------------------------------------------------
# Application / glue (this repo). Unified main.c is gated by NO_CRYPT_TEST,
# NO_CRYPT_BENCHMARK, and WOLFMQTT_DEMO so a single file serves all targets.
SRC_C  := \
  src/main.c \
  src/hw_init.c \
  src/semihost.c \
  src/stubs.c \
  src/stm32u3xx_hal_msp.c \
  src/stm32u3xx_it.c

# Per-target main.c feature gates
ifeq ($(TARGET),test)
  COMMON_DEFS += -DNO_CRYPT_BENCHMARK
endif
ifeq ($(TARGET),bench)
  COMMON_DEFS += -DNO_CRYPT_TEST
endif
ifeq ($(TARGET),app)
  COMMON_DEFS += -DNO_CRYPT_TEST -DNO_CRYPT_BENCHMARK -DWOLFMQTT_DEMO
endif

# DHUK=1 makes the TLS client authenticate with a DHUK-wrapped private key
# instead of one loaded from a buffer (src/dhuk_key.c). Needs the SAES+PKA
# silicon, so it is U385-only, and AES-ECB for the provisioning wrap, which the
# TLS 1.3 profile does not otherwise pull in. wolfCrypt's ECB decrypt is built
# on the AES direct API, hence WOLFSSL_AES_DIRECT.
# Applies to "make app DHUK=1"; the other targets build no TLS client and
# ignore it. CONFIG=hw only: that variant builds the HAL crypto the SAES path
# needs, and the device key path is outside the FIPS boundary.
ifeq ($(DHUK)$(TARGET),1app)
  ifneq ($(CONFIG),hw)
    $(error DHUK=1 requires CONFIG=hw)
  endif
  COMMON_DEFS += -DDEMO_DHUK_CLIENT_KEY -DWOLFSSL_DHUK -DWOLF_CRYPTO_CB \
                 -DWOLFSSL_STM32_PKA -DHAVE_AES_ECB -DWOLFSSL_AES_DIRECT
  SRC_C += src/dhuk_key.c
endif

# CMSIS device files come from the STM32Cube U3 pack (NUCLEO-U385RG-Q
# CubeIDE template — matches what we used to ship in src/, no MSPLIM use).
PACK_NUCLEO_DIR := $(STM32CUBE_FW_U3)/Projects/NUCLEO-U385RG-Q/Templates_Board
SRC_C  += $(PACK_NUCLEO_DIR)/Src/system_stm32u3xx.c
SRC_ASM := $(PACK_NUCLEO_DIR)/STM32CubeIDE/Application/Startup/startup_stm32u385rgtxq.s

# STM32Cube HAL — compile only the modules we actually enable in hal_conf.h
HAL_SRC_DIR := $(STM32CUBE_FW_U3)/Drivers/STM32U3xx_HAL_Driver/Src
HAL_SOURCES := \
  stm32u3xx_hal.c \
  stm32u3xx_hal_cortex.c \
  stm32u3xx_hal_dma.c \
  stm32u3xx_hal_dma_ex.c \
  stm32u3xx_hal_exti.c \
  stm32u3xx_hal_flash.c \
  stm32u3xx_hal_flash_ex.c \
  stm32u3xx_hal_gpio.c \
  stm32u3xx_hal_icache.c \
  stm32u3xx_hal_pwr.c \
  stm32u3xx_hal_pwr_ex.c \
  stm32u3xx_hal_rcc.c \
  stm32u3xx_hal_rcc_ex.c \
  stm32u3xx_hal_rng.c \
  stm32u3xx_hal_rng_ex.c \
  stm32u3xx_hal_uart.c \
  stm32u3xx_hal_uart_ex.c

ifeq ($(CONFIG),hw)
HAL_SOURCES += stm32u3xx_hal_hash.c stm32u3xx_hal_cryp.c stm32u3xx_hal_cryp_ex.c
endif

ifeq ($(DHUK)$(TARGET),1app)
HAL_SOURCES += stm32u3xx_hal_pka.c
endif

HAL_SRC := $(addprefix $(HAL_SRC_DIR)/,$(HAL_SOURCES))

# wolfCrypt — compile the whole wolfcrypt/src tree; user_settings gates out
# what isn't needed.
WC_SRC_DIR := $(WOLFSSL_ROOT)/wolfcrypt/src
WC_ALL     := $(wildcard $(WC_SRC_DIR)/*.c)
# Always exclude these
WC_EXCLUDE := \
  $(WC_SRC_DIR)/evp.c \
  $(WC_SRC_DIR)/misc.c \
  $(WC_SRC_DIR)/selftest.c \
  $(WC_SRC_DIR)/async.c

ifeq ($(CONFIG),fips)
  # FIPS build: include boundary markers and fips.c/fips_test.c
  # wolfcrypt_first.o must link first, wolfcrypt_last.o must link last
  WC_EXCLUDE += $(WC_SRC_DIR)/wolfcrypt_first.c $(WC_SRC_DIR)/wolfcrypt_last.c
  WC_FIPS_FIRST := $(WC_SRC_DIR)/wolfcrypt_first.c
  WC_FIPS_LAST  := $(WC_SRC_DIR)/wolfcrypt_last.c
else
  # Non-FIPS: exclude FIPS boundary and module files
  WC_EXCLUDE += \
    $(WC_SRC_DIR)/wolfcrypt_first.c \
    $(WC_SRC_DIR)/wolfcrypt_last.c \
    $(WC_SRC_DIR)/fips.c \
    $(WC_SRC_DIR)/fips_test.c
  WC_FIPS_FIRST :=
  WC_FIPS_LAST  :=
endif

# Include STM32 port (always; body no-ops when defines absent)
WC_SRC := $(filter-out $(WC_EXCLUDE),$(WC_ALL)) \
          $(WC_SRC_DIR)/port/st/stm32.c

# Driver (test / bench / app)
ifeq ($(TARGET),test)
  SRC_C += $(WOLFSSL_ROOT)/wolfcrypt/test/test.c
endif
ifeq ($(TARGET),bench)
  SRC_C += $(WOLFSSL_ROOT)/wolfcrypt/benchmark/benchmark.c
endif
ifeq ($(TARGET),app)
  SRC_C += src/uart_net.c
  # wolfSSL TLS sources (exclude ssl_misc.c — inlined, and bio/ocsp stubs)
  WOLFSSL_TLS_ALL := $(wildcard $(WOLFSSL_ROOT)/src/*.c)
  WOLFSSL_TLS_EXCLUDE := $(WOLFSSL_ROOT)/src/ssl_misc.c \
                         $(WOLFSSL_ROOT)/src/bio.c
  SRC_C += $(filter-out $(WOLFSSL_TLS_EXCLUDE),$(WOLFSSL_TLS_ALL))
  # wolfMQTT
  SRC_C += $(wildcard $(WOLFMQTT_ROOT)/src/*.c)
  INCLUDES += -I$(WOLFMQTT_ROOT)
  COMMON_DEFS += -DWOLFMQTT_USER_SETTINGS
endif

# For FIPS, wolfcrypt_first must come before all other wolfcrypt sources
# and wolfcrypt_last must come after. Use WC_FIPS_FIRST / WC_FIPS_LAST.
ALL_C_SRC := $(SRC_C) $(WC_FIPS_FIRST) $(WC_SRC) $(WC_FIPS_LAST) $(HAL_SRC)

# ----- Object files -------------------------------------------------------
# Objects mirror source tree under build/obj/
rel_obj = $(BUILD_DIR)/obj/$(subst /,__,$(patsubst /%,%,$(1))).o

C_OBJ   := $(foreach s,$(ALL_C_SRC),$(call rel_obj,$(s)))
ASM_OBJ := $(foreach s,$(SRC_ASM),$(call rel_obj,$(s)))
OBJS    := $(C_OBJ) $(ASM_OBJ)
DEPS    := $(OBJS:.o=.d)

# ----- Default target ------------------------------------------------------
.PHONY: all test bench app flash size clean distclean size-report \
       wb-build wb-keys wb-app wb-sign wb-flash
all: test

test:
	$(MAKE) build TARGET=test

bench:
	$(MAKE) build TARGET=bench

app:
	$(MAKE) build TARGET=app

build: $(BUILD_DIR)/app.bin $(BUILD_DIR)/app.hex size

# ----- Rules --------------------------------------------------------------
$(BUILD_DIR):
	@mkdir -p $(BUILD_DIR)/obj

# Dynamic pattern: each source gets a unique munged object path.
define COMPILE_C_TEMPLATE
$(call rel_obj,$(1)): $(1) | $(BUILD_DIR)
	@echo "  CC   $$<"
	@mkdir -p $$(@D)
	@$(CC) $(CFLAGS) -c $$< -o $$@
endef

define COMPILE_ASM_TEMPLATE
$(call rel_obj,$(1)): $(1) | $(BUILD_DIR)
	@echo "  AS   $$<"
	@mkdir -p $$(@D)
	@$(AS) $(ASFLAGS) -c $$< -o $$@
endef

$(foreach s,$(ALL_C_SRC),$(eval $(call COMPILE_C_TEMPLATE,$(s))))
$(foreach s,$(SRC_ASM),$(eval $(call COMPILE_ASM_TEMPLATE,$(s))))

$(BUILD_DIR)/app.elf: $(OBJS) $(LDSCRIPT)
	@echo "  LD   $@"
	@$(CC) $(LDFLAGS) -o $@ $(OBJS) $(LDLIBS)

$(BUILD_DIR)/app.bin: $(BUILD_DIR)/app.elf
	@echo "  BIN  $@"
	@$(OBJCOPY) -O binary $< $@

$(BUILD_DIR)/app.hex: $(BUILD_DIR)/app.elf
	@$(OBJCOPY) -O ihex $< $@

size: $(BUILD_DIR)/app.elf
	@echo
	@echo "----- size: $(notdir $(BUILD_DIR)) -----"
	@$(SIZE) $<

# st-flash does NOT support STM32U3 (chipid 0x454). Use STM32_Programmer_CLI.
# Set SN= when more than one ST-LINK is attached, or the programmer picks
# whichever enumerates first and writes to the wrong board:
#   make flash SN=0034004C3333511631363730     (st-info --probe lists them)
SN ?=
SN_ARG := $(if $(SN),sn=$(SN),)

# Override on cmd line: make flash STM32_PROG=/path/to/STM32_Programmer_CLI
STM32_PROG ?= /opt/st/stm32cubeide_2.0.0/plugins/com.st.stm32cube.ide.mcu.externaltools.cubeprogrammer.linux64_2.2.300.202508131133/tools/bin/STM32_Programmer_CLI

flash: $(BUILD_DIR)/app.bin
	$(STM32_PROG) -c port=SWD $(SN_ARG) reset=HWrst -e all -d $(BUILD_DIR)/app.bin 0x08000000 -v -rst

size-report:
	@echo "== STM32U385RG_Nucleo_MQTT size report =="
	@for d in build/*; do \
	  if [ -f $$d/app.elf ]; then \
	    echo "--- $$d ---"; \
	    $(SIZE) $$d/app.elf; \
	  fi; \
	done

clean:
	rm -rf $(BUILD_DIR)

distclean:
	rm -rf build

# ----- wolfBoot integration (Phase 5) ------------------------------------
# wolfBoot flash layout (STM32U385RG dual-bank, 4 KB pages):
#   0x08000000  wolfBoot bootloader           64 KB (Bank 1)
#   0x08010000  BOOT partition (app image)   448 KB (Bank 1)
#   0x08080000  UPDATE partition             448 KB (Bank 2)
#   0x080F0000  SWAP sector                    4 KB (Bank 2)
WB_IMG_HDR_SIZE := 256
WB_BOOT_ADDR    := 0x08010000
WB_APP_ADDR     := 0x08010200   # 0x08010000 + 0x200 manifest (ECC384+SHA384)
WB_SIGN_TOOL    := $(WOLFBOOT_ROOT)/tools/keytools/sign
WB_KEYGEN_TOOL  := $(WOLFBOOT_ROOT)/tools/keytools/keygen
WB_PRIV_KEY     := $(WOLFBOOT_ROOT)/wolfboot_signing_private_key.der
WB_APP_VERSION  ?= 1

wb-build:
	@echo "=== Building wolfBoot ==="
	@if [ ! -d "$(WOLFBOOT_ROOT)/hal" ]; then \
	  echo "ERROR: WOLFBOOT_ROOT=$(WOLFBOOT_ROOT) not found"; exit 1; fi
	cp $(WOLFBOOT_ROOT)/config/examples/stm32u3.config $(WOLFBOOT_ROOT)/.config
	$(MAKE) -C $(WOLFBOOT_ROOT) keytools
	$(MAKE) -C $(WOLFBOOT_ROOT)
	@echo "wolfBoot built:"
	@$(SIZE) $(WOLFBOOT_ROOT)/wolfboot.elf

wb-keys:
	@echo "=== Generating wolfBoot signing keys (ECC384) ==="
	$(WB_KEYGEN_TOOL) --ecc384 -g $(WB_PRIV_KEY)
	@echo "Private key: $(WB_PRIV_KEY)"
	@echo "Public key store: $(WOLFBOOT_ROOT)/src/keystore.c (rebuild wolfBoot)"

wb-app:
	@echo "=== Building wolfBoot-linked app (CONFIG=$(CONFIG)) ==="
	$(MAKE) build TARGET=app WOLFBOOT=1

# wb-* targets always operate on the 'app' build dir regardless of TARGET=
WB_APP_DIR := $(TOP)/build/app-$(CONFIG)$(DHUK_SUFFIX)-wb

wb-sign: wb-app
	@echo "=== Signing app image (ECC384 / SHA384, v$(WB_APP_VERSION)) ==="
	@if [ ! -f "$(WB_PRIV_KEY)" ]; then \
	  echo "ERROR: private key not found at $(WB_PRIV_KEY)"; \
	  echo "Run 'make wb-keys' first"; exit 1; fi
	$(WB_SIGN_TOOL) --ecc384 --sha384 \
	  $(WB_APP_DIR)/app.bin $(WB_PRIV_KEY) $(WB_APP_VERSION)
	@echo "Signed image: $(WB_APP_DIR)/app_v$(WB_APP_VERSION)_signed.bin"
	@ls -la $(WB_APP_DIR)/app_v*_signed.bin

wb-flash:
	@echo "=== Flashing wolfBoot + signed app ==="
	@if [ ! -f "$(WOLFBOOT_ROOT)/wolfboot.bin" ]; then \
	  echo "ERROR: wolfboot.bin not found. Run 'make wb-build' first"; exit 1; fi
	$(STM32_PROG) -c port=SWD $(SN_ARG) reset=HWrst -e all \
	  -d $(WOLFBOOT_ROOT)/wolfboot.bin 0x08000000 \
	  -d $(WB_APP_DIR)/app_v$(WB_APP_VERSION)_signed.bin $(WB_BOOT_ADDR) -v -rst
	@echo "Flashed. Reset the board to boot."

# ----- Dependency files ---------------------------------------------------
-include $(DEPS)
