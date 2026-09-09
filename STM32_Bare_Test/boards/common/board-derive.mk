# ---------------------------------------------------------------------------
# board-derive.mk - shared resolver for the per-board boards/<BOARD>/board.mk
# fragments. Included once, right after the selected board.mk.
#
# A board.mk sets a small set of raw atoms; everything mechanical is computed
# here so the per-board fragments stay short. Every value below is assigned
# only when the board.mk (or its family.mk) did not already set it, so any
# board can override any derived field by assigning it explicitly.
#
# Atoms a board.mk / family.mk provides:
#   CUBE_FW_VAR     env-overridable cube pack var name (e.g. STM32CUBE_FW_H5)
#   CUBE_FW_DEFAULT default path for that pack
#   HAL_FAMILY      CMSIS/HAL family token, mixed case (e.g. H5xx); empty for
#                   BARE-only families with no HAL wiring (C5)
#   HAL_CONF_SHORT  cubemx/<short> conf dir leaf (e.g. h5)
#   OPENOCD_TARGET  openocd target cfg (e.g. stm32h5x.cfg)
#   b_chip          lowercase chip basename for ld/startup/define (e.g. h563)
#   b_core          MCU core profile key (see table below)
#   b_serial        ST-LINK serial (-> STLINK_SERIAL)
#   b_system        board system_stm32*.c source
# Optional overrides:
#   b_chipdef       -D token if not STM32<upper(b_chip)>xx (h7a3, f303)
#   b_extra_defs    extra compiler flags appended to CPU_DEFS unconditionally
#                   (defines or tuning flags: wl55 -DCORE_CM4, v8 -mtune=...)
#   b_hal_v2        1 -> add -DSTM32_HAL_V2 under BUILD=cubemx (f4 v1.28+, u0)
#   b_ldsuffix      ld basename suffix, default "flat" (n657/h7s3 use "lrun")
#   STLINK_SERIAL / USE_CUBE_PROGRAMMER / LDSCRIPT / STARTUP_S /
#   BOARD_C_SRC / CMSIS_DEVICE / CMSIS_CORE / CPU_DEFS / MCU_FLAGS
#                   may all be set directly by a board.mk to win over the
#                   derivation below.
# ---------------------------------------------------------------------------

uc = $(shell echo '$(1)' | tr '[:lower:]' '[:upper:]')
lc = $(shell echo '$(1)' | tr '[:upper:]' '[:lower:]')

BCHIP_UC := $(call uc,$(b_chip))
BOARD_UC := $(call uc,$(BOARD))

# ---- MCU core profiles -----------------------------------------------------
ifndef MCU_FLAGS
  ifeq ($(b_core),m33f)
    MCU_FLAGS := -mcpu=cortex-m33 -mthumb -mfpu=fpv5-sp-d16 -mfloat-abi=hard
  endif
  ifeq ($(b_core),m33f_cmse)
    MCU_FLAGS := -mcpu=cortex-m33 -mthumb -mfpu=fpv5-sp-d16 -mfloat-abi=hard -mcmse
  endif
  ifeq ($(b_core),m7sp)
    MCU_FLAGS := -mcpu=cortex-m7 -mthumb -mfpu=fpv5-sp-d16 -mfloat-abi=hard
  endif
  ifeq ($(b_core),m7dp)
    MCU_FLAGS := -mcpu=cortex-m7 -mthumb -mfpu=fpv5-d16 -mfloat-abi=hard
  endif
  ifeq ($(b_core),m4f)
    MCU_FLAGS := -mcpu=cortex-m4 -mthumb -mfpu=fpv4-sp-d16 -mfloat-abi=hard
  endif
  ifeq ($(b_core),m4soft)
    MCU_FLAGS := -mcpu=cortex-m4 -mthumb -mfloat-abi=soft
  endif
  ifeq ($(b_core),m3soft)
    MCU_FLAGS := -mcpu=cortex-m3 -mthumb -mfloat-abi=soft
  endif
  ifeq ($(b_core),m0plus_soft)
    MCU_FLAGS := -mcpu=cortex-m0plus -mthumb -mfloat-abi=soft
  endif
  ifeq ($(b_core),m0plus)
    MCU_FLAGS := -mcpu=cortex-m0plus -mthumb
  endif
  ifeq ($(b_core),m55)
    MCU_FLAGS := -mcpu=cortex-m55 -mthumb -mfpu=fpv5-d16 -mfloat-abi=hard
  endif
  # Cortex-M85 (Armv8.1-M, STM32V8). No -mfpu=: -mcpu=cortex-m85 already
  # selects the correct FPU. +nomve is load-bearing -- GCC defines
  # __ARM_FEATURE_MVE 3 by default on this core, so without it the
  # autovectorizer quietly puts Helium into what we report as the pure
  # software baseline. Use b_core=m85_mve for the deliberate A/B.
  ifeq ($(b_core),m85)
    MCU_FLAGS := -mcpu=cortex-m85+nomve -mthumb -mfloat-abi=hard
  endif
  ifeq ($(b_core),m85_mve)
    MCU_FLAGS := -mcpu=cortex-m85 -mthumb -mfloat-abi=hard
  endif
  ifndef MCU_FLAGS
    $(error board.mk for $(BOARD) set b_core=$(b_core) which board-derive.mk \
            does not know; add it to the MCU core profile table)
  endif
endif

# ---- Cube pack + CMSIS -----------------------------------------------------
ifdef CUBE_FW_VAR
  $(CUBE_FW_VAR) ?= $(CUBE_FW_DEFAULT)
  CUBE_DIR       ?= $($(CUBE_FW_VAR))
endif
ifneq ($(HAL_FAMILY),)
  HAL_FAMILY_LC ?= $(call lc,$(HAL_FAMILY))
  CMSIS_DEVICE  ?= $(CUBE_DIR)/Drivers/CMSIS/Device/ST/STM32$(HAL_FAMILY)/Include
  CMSIS_CORE    ?= $(CUBE_DIR)/Drivers/CMSIS/Core/Include
  HAL_CONF_DIR  ?= $(TOP)/cubemx/$(HAL_CONF_SHORT)
endif

# ---- CPU + board defines ---------------------------------------------------
b_chipdef ?= STM32$(BCHIP_UC)xx
ifndef CPU_DEFS
  CPU_DEFS := -D$(b_chipdef) -DSTM32_BOARD_$(BOARD_UC) $(b_extra_defs)
endif
ifeq ($(BUILD),cubemx)
  ifeq ($(b_hal_v2),1)
    CPU_DEFS += -DSTM32_HAL_V2
  endif
  # b_hal_newgen 1 -> this part ships ST's new-generation HAL (HAL2, e.g. C5),
  # which has no classic CRYP/PKA/CCB/RNG driver APIs. wolfcrypt stays on its
  # register (BARE) crypto path; the new-gen HAL handles only board bring-up.
  # STM32_HAL_V2 (the classic CRYP "v2" API) is unrelated and not used here.
  ifeq ($(b_hal_newgen),1)
    # _RTE_ makes the new-gen HAL pull its stm32<f>xx_hal_conf.h (the
    # USE_HAL_*_MODULE enables); without it the module headers compile out.
    CPU_DEFS += -DSTM32_HAL_NEWGEN -D_RTE_
  endif
endif

# ---- Linker script + startup -----------------------------------------------
b_ldsuffix ?= flat
LDSCRIPT   ?= $(TOP)/boards/$(BOARD)/stm32$(b_chip)_$(b_ldsuffix).ld
STARTUP_S  ?= boards/$(BOARD)/startup_stm32$(b_chip)xx.s

# ---- Board C sources (system + bring-up) -----------------------------------
ifeq ($(BUILD),cubemx)
  HW_INIT := boards/$(BOARD)/hw_init_cubemx.c
else
  HW_INIT := boards/$(BOARD)/hw_init.c
endif
BOARD_C_SRC ?= $(b_system) $(HW_INIT)

# ---- ST-LINK serial --------------------------------------------------------
ifdef b_serial
  STLINK_SERIAL ?= $(b_serial)
endif
