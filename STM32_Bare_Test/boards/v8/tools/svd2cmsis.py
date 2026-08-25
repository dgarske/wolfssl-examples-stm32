#!/usr/bin/env python3
"""Generate a minimal CMSIS device header from a CMSIS-SVD file.

Written for the STM32V8 (NUCLEO-V873XJ) bring-up, where ST publishes no
device family pack: STM32CubeProgrammer 2.22.0 ships a complete
SVD/STM32V873.svd, and that file is what a CMSIS header is generated from.

The OUTPUT of this script is derived from ST's SVD and is deliberately NOT
checked in -- generate it locally, the same way boards/c5a3 points at a
CubeIDE workspace DFP rather than vendoring one.

Only the peripherals a bare-metal wolfCrypt build touches are emitted, which
keeps the result reviewable. Add to PERIPHERALS below as needed.

Usage:
  ./svd2cmsis.py --svd <path to STM32V873.svd> --out <dir> [--all]

Produces <dir>/stm32v8xx.h (and a stm32v873xx.h alias) for use as
STM32V8_DFP=<dir>/.. -- see boards/v8/board.mk.
"""

import argparse
import os
import re
import sys
import xml.etree.ElementTree as ET

# Peripherals needed by wolfCrypt's STM32 BARE path plus board bring-up.
PERIPHERALS = [
    'RCC', 'PWR', 'FLASH',
    'HASH', 'CRYP', 'SAES', 'PKA', 'RNG', 'CCB',
    'GPIOA', 'GPIOB', 'GPIOC', 'GPIOD', 'GPIOE', 'GPIOF', 'GPIOG',
    'GPIOH', 'GPIOI', 'GPIOJ', 'GPIOK', 'GPIOM',
    'USART1', 'USART2', 'USART3', 'USART6', 'USART10',
    'UART4', 'UART5', 'UART7', 'UART8', 'UART9', 'LPUART1',
]



# V2 PKA operand RAM word-offsets. These are properties of the PKA IP
# firmware, not register fields, so they do not appear in the SVD; the
# values are byte-identical across every V2 part checked (STM32N6, STM32U5).
# Word index = (byte_offset - 0x400) >> 2, matching ST's convention.
PKA_V2_RAM_OFFSETS = [
    ('PKA_ECC_SCALAR_MUL_IN_A_COEFF', 0x0418),
    ('PKA_ECC_SCALAR_MUL_IN_A_COEFF_SIGN', 0x0410),
    ('PKA_ECC_SCALAR_MUL_IN_B_COEFF', 0x0520),
    ('PKA_ECC_SCALAR_MUL_IN_EXP_NB_BITS', 0x0400),
    ('PKA_ECC_SCALAR_MUL_IN_INITIAL_POINT_X', 0x0578),
    ('PKA_ECC_SCALAR_MUL_IN_INITIAL_POINT_Y', 0x0470),
    ('PKA_ECC_SCALAR_MUL_IN_K', 0x12A0),
    ('PKA_ECC_SCALAR_MUL_IN_MOD_GF', 0x1088),
    ('PKA_ECC_SCALAR_MUL_IN_N_PRIME_ORDER', 0x0F88),
    ('PKA_ECC_SCALAR_MUL_IN_OP_NB_BITS', 0x0408),
    ('PKA_ECC_SCALAR_MUL_OUT_RESULT_X', 0x0578),
    ('PKA_ECC_SCALAR_MUL_OUT_RESULT_Y', 0x05D0),
    ('PKA_ECDSA_SIGN_IN_A_COEFF', 0x0418),
    ('PKA_ECDSA_SIGN_IN_A_COEFF_SIGN', 0x0410),
    ('PKA_ECDSA_SIGN_IN_B_COEFF', 0x0520),
    ('PKA_ECDSA_SIGN_IN_HASH_E', 0x0FE8),
    ('PKA_ECDSA_SIGN_IN_INITIAL_POINT_X', 0x0578),
    ('PKA_ECDSA_SIGN_IN_INITIAL_POINT_Y', 0x0470),
    ('PKA_ECDSA_SIGN_IN_K', 0x12A0),
    ('PKA_ECDSA_SIGN_IN_MOD_GF', 0x1088),
    ('PKA_ECDSA_SIGN_IN_MOD_NB_BITS', 0x0408),
    ('PKA_ECDSA_SIGN_IN_ORDER_N', 0x0F88),
    ('PKA_ECDSA_SIGN_IN_ORDER_NB_BITS', 0x0400),
    ('PKA_ECDSA_SIGN_IN_PRIVATE_KEY_D', 0x0F28),
    ('PKA_ECDSA_SIGN_OUT_ERROR', 0x0FE0),
    ('PKA_ECDSA_SIGN_OUT_FINAL_POINT_X', 0x1400),
    ('PKA_ECDSA_SIGN_OUT_FINAL_POINT_Y', 0x1458),
    ('PKA_ECDSA_SIGN_OUT_SIGNATURE_R', 0x0730),
    ('PKA_ECDSA_SIGN_OUT_SIGNATURE_S', 0x0788),
    ('PKA_ECDSA_VERIF_IN_A_COEFF', 0x0470),
    ('PKA_ECDSA_VERIF_IN_A_COEFF_SIGN', 0x0468),
    ('PKA_ECDSA_VERIF_IN_HASH_E', 0x13A8),
    ('PKA_ECDSA_VERIF_IN_INITIAL_POINT_X', 0x0678),
    ('PKA_ECDSA_VERIF_IN_INITIAL_POINT_Y', 0x06D0),
    ('PKA_ECDSA_VERIF_IN_MOD_GF', 0x04D0),
    ('PKA_ECDSA_VERIF_IN_MOD_NB_BITS', 0x04C8),
    ('PKA_ECDSA_VERIF_IN_ORDER_N', 0x1088),
    ('PKA_ECDSA_VERIF_IN_ORDER_NB_BITS', 0x0408),
    ('PKA_ECDSA_VERIF_IN_PUBLIC_KEY_POINT_X', 0x12F8),
    ('PKA_ECDSA_VERIF_IN_PUBLIC_KEY_POINT_Y', 0x1350),
    ('PKA_ECDSA_VERIF_IN_SIGNATURE_R', 0x10E0),
    ('PKA_ECDSA_VERIF_IN_SIGNATURE_S', 0x0C68),
    ('PKA_ECDSA_VERIF_OUT_RESULT', 0x05D0),
]


def text(node, tag, default=None):
    if node is None:
        return default
    v = node.findtext(tag)
    return v if v is not None else default


def num(s, default=0):
    if s is None:
        return default
    s = s.strip()
    try:
        return int(s, 0)
    except ValueError:
        return default


def resolve(root):
    """Return {name: (element, base, derived_source_element)}."""
    by_name = {}
    for p in root.iter('peripheral'):
        by_name[text(p, 'name')] = p
    out = {}
    for name, p in by_name.items():
        src = p
        df = p.get('derivedFrom')
        if df and df in by_name:
            src = by_name[df]
        out[name] = (p, num(text(p, 'baseAddress')), src)
    return out


def registers(per_el):
    regs = []
    for r in per_el.iter('register'):
        regs.append({
            'name': text(r, 'name'),
            'off': num(text(r, 'addressOffset')),
            'size': num(text(r, 'size'), 32) // 8 or 4,
            'access': text(r, 'access'),
            'el': r,
        })
    regs.sort(key=lambda x: x['off'])
    return regs


def strip_prefix(regname, pername):
    """SVD names registers HASH_CR; CMSIS structs call the member CR."""
    for pre in (pername + '_', pername.rstrip('0123456789') + '_'):
        if regname.startswith(pre) and len(regname) > len(pre):
            return regname[len(pre):]
    return regname


def coalesce(regs, pername):
    """Fold contiguous numbered runs (CSR0..CSR102) into arrays (CSR[103]).

    wolfSSL indexes HASH->CSR[i] / HASH->HR[i], so this is required, not
    cosmetic.
    """
    items = []
    i = 0
    named = [(strip_prefix(r['name'], pername), r) for r in regs]
    while i < len(named):
        nm, r = named[i]
        m = re.match(r'^(.*?)(\d+)$', nm)
        if m:
            stem, idx = m.group(1), int(m.group(2))
            j, count, expect_off, expect_idx = i, 0, r['off'], idx
            while j < len(named):
                nm2, r2 = named[j]
                m2 = re.match(r'^(.*?)(\d+)$', nm2)
                if (not m2 or m2.group(1) != stem
                        or int(m2.group(2)) != expect_idx
                        or r2['off'] != expect_off):
                    break
                count += 1
                expect_idx += 1
                expect_off += r2['size']
                j += 1
            # ST convention coalesces only the HASH context/digest banks
            # (CSR[103], HR[], HRA[]) into arrays; everything else -- SAES
            # KEYR0..7, SUSPR0..7, CRYP CSGCMCCM0..7R -- stays discrete,
            # and wolfSSL's drivers index them by those discrete names.
            if count > 1 and idx == 0 and stem in ('CSR', 'HR', 'HRA'):
                items.append({'kind': 'array', 'name': stem, 'count': count,
                              'off': r['off'], 'size': r['size'],
                              'regs': [x[1] for x in named[i:j]]})
                i = j
                continue
        items.append({'kind': 'reg', 'name': nm, 'off': r['off'],
                      'size': r['size'], 'reg': r})
        i += 1
    return items


def ctype(size, access):
    base = {1: 'uint8_t', 2: 'uint16_t', 4: 'uint32_t'}.get(size, 'uint32_t')
    if access == 'read-only':
        return '__IM  ' + base
    if access == 'write-only':
        return '__OM  ' + base
    return '__IOM ' + base


def emit_struct(pername, per_el, out):
    regs = registers(per_el)
    if not regs:
        return False
    items = coalesce(regs, pername)
    out.append('typedef struct {')
    cursor = 0
    pad = 0
    for it in items:
        if it['off'] > cursor:
            gap = it['off'] - cursor
            out.append('  __IM  uint8_t  RESERVED%d[%d];' % (pad, gap))
            pad += 1
            cursor = it['off']
        elif it['off'] < cursor:
            # overlapping/aliased register - skip, the first definition wins
            continue
        if it['kind'] == 'array':
            acc = it['regs'][0]['access']
            out.append('  %s %s[%d];' % (ctype(it['size'], acc), it['name'],
                                         it['count']))
            cursor += it['size'] * it['count']
        else:
            out.append('  %s %s;' % (ctype(it['size'], it['reg']['access']),
                                     it['name']))
            cursor += it['size']
    if pername == 'PKA':
        # ST's PKA_TypeDef carries the operand RAM after the registers:
        # pad to 0x400, then RAM[1334] words (matches N6/U5 headers; the
        # SVD describes only the registers). The driver indexes PKA->RAM[].
        if cursor < 0x400:
            out.append('  __IM  uint8_t  RESERVED%d[%d];' % (pad, 0x400 - cursor))
            pad += 1
        out.append('  __IOM uint32_t RAM[1334];')
    out.append('} %s_TypeDef;' % pername)
    out.append('')
    return True


def emit_fields(pername, per_el, out):
    seen = set()
    for r in per_el.iter('register'):
        rn = text(r, 'name')
        for f in r.iter('field'):
            fn = text(f, 'name')
            off = num(text(f, 'bitOffset'))
            width = num(text(f, 'bitWidth'), 1)
            macro = '%s_%s' % (rn, fn)
            if macro in seen:
                continue
            seen.add(macro)
            mask = ((1 << width) - 1) << off
            out.append('#define %s_Pos  (%du)' % (macro, off))
            out.append('#define %s_Msk  (0x%XUL)' % (macro, mask))
            out.append('#define %s      %s_Msk' % (macro, macro))
            if width > 1:
                # ST convention: each bit of a multi-bit field also gets its
                # own _n macro (e.g. HASH_CR_ALGO_0..3); consumers such as
                # wolfSSL build algorithm-select values from these.
                for bit in range(width):
                    out.append('#define %s_%d  (0x%XUL)'
                               % (macro, bit, 1 << (off + bit)))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--svd', required=True)
    ap.add_argument('--out', required=True)
    ap.add_argument('--all', action='store_true',
                    help='emit every peripheral, not just the wolfCrypt set')
    args = ap.parse_args()

    root = ET.parse(args.svd).getroot()
    res = resolve(root)
    device = text(root, 'name', 'STM32V873')

    wanted = sorted(res.keys()) if args.all else PERIPHERALS

    out = []
    out.append('/* Generated by svd2cmsis.py from %s -- DO NOT EDIT, DO NOT'
               % os.path.basename(args.svd))
    out.append(' * CHECK IN. Derived from STMicroelectronics SVD data; keep it')
    out.append(' * local like a vendor DFP. Regenerate with boards/v8/tools.')
    out.append(' */')
    out.append('#ifndef STM32V8XX_H')
    out.append('#define STM32V8XX_H')
    out.append('#ifdef __cplusplus')
    out.append('extern "C" {')
    out.append('#endif')
    out.append('')
    out.append('#include <stdint.h>')
    out.append('')

    # ---- interrupt numbers ----
    irqs = {}
    for p in root.iter('peripheral'):
        for it in p.iter('interrupt'):
            irqs.setdefault(num(text(it, 'value')), text(it, 'name'))
    out.append('typedef enum {')
    out.append('  NonMaskableInt_IRQn   = -14,')
    out.append('  HardFault_IRQn        = -13,')
    out.append('  MemoryManagement_IRQn = -12,')
    out.append('  BusFault_IRQn         = -11,')
    out.append('  UsageFault_IRQn       = -10,')
    out.append('  SecureFault_IRQn      = -9,')
    out.append('  SVCall_IRQn           = -5,')
    out.append('  DebugMonitor_IRQn     = -4,')
    out.append('  PendSV_IRQn           = -2,')
    out.append('  SysTick_IRQn          = -1,')
    for v in sorted(irqs):
        out.append('  %s_IRQn = %d,' % (irqs[v], v))
    out.append('} IRQn_Type;')
    out.append('')

    # ---- core configuration (SVD carries no <cpu> element) ----
    out.append('#define __CM85_REV              0x0001U')
    out.append('#define __NVIC_PRIO_BITS        4U')
    out.append('#define __Vendor_SysTickConfig  0U')
    out.append('#define __FPU_PRESENT           1U')
    out.append('#define __MPU_PRESENT           1U')
    out.append('#define __DSP_PRESENT           1U')
    out.append('#define __ICACHE_PRESENT        1U')
    out.append('#define __DCACHE_PRESENT        1U')
    out.append('#define __SAUREGION_PRESENT     1U')
    out.append('#include "core_cm85.h"')
    out.append('')

    emitted = []
    for name in wanted:
        if name not in res:
            continue
        per_el, base, src = res[name]
        if src is per_el:
            if emit_struct(name, per_el, out):
                emitted.append(name)
        else:
            emitted.append(name)

    # ---- bases and instances (including _S secure aliases) ----
    out.append('')
    for name in sorted(res):
        stem = name[:-2] if name.endswith('_S') else name
        if stem not in emitted:
            continue
        per_el, base, src = res[name]
        sname = text(src, 'name')
        tname = (sname[:-2] if sname.endswith('_S') else sname) + '_TypeDef'
        out.append('#define %s_BASE (0x%08XUL)' % (name, base))
        out.append('#define %s ((%s *)%s_BASE)' % (name, tname, name))
    out.append('')

    # ---- HASH_DIGEST compat instance (ST convention) ----
    # ST headers expose the extended digest bank (HR0..15 at HASH_BASE+0x310)
    # as a separate HASH_DIGEST peripheral; wolfSSL keys its whole SHA-2/SHA-3
    # HASH capability tree on '#ifdef HASH_DIGEST' and reads
    # HASH_DIGEST->HR[i]. Emit the same shape.
    if 'HASH' in emitted:
        out.append('')
        out.append('typedef struct {')
        out.append('  __IOM uint32_t HR[16];')
        out.append('} HASH_DIGEST_TypeDef;')
        out.append('#define HASH_DIGEST_BASE (%s_BASE + 0x310UL)'
                   % 'HASH')
        out.append('#define HASH_DIGEST ((HASH_DIGEST_TypeDef *)HASH_DIGEST_BASE)')
        out.append('#define HASH_DIGEST_S ((HASH_DIGEST_TypeDef *)(HASH_S_BASE + 0x310UL))')

    # ---- V2 PKA operand RAM offsets (IP constants, not SVD material) ----
    if 'PKA' in emitted:
        out.append('')
        out.append('#define PKA_RAM_OFFSET  (0x0400UL)')
        for nm, byteoff in PKA_V2_RAM_OFFSETS:
            out.append('#define %s  ((0x%04XUL - PKA_RAM_OFFSET)>>2)'
                       % (nm, byteoff))

    # ---- field macros ----
    for name in emitted:
        per_el, base, src = res[name]
        if src is per_el:
            emit_fields(name, per_el, out)
    out.append('')
    out.append('#ifdef __cplusplus')
    out.append('}')
    out.append('#endif')
    out.append('#endif /* STM32V8XX_H */')

    os.makedirs(args.out, exist_ok=True)
    path = os.path.join(args.out, 'stm32v8xx.h')
    with open(path, 'w') as fh:
        fh.write('\n'.join(out) + '\n')
    alias = os.path.join(args.out, 'stm32v873xx.h')
    with open(alias, 'w') as fh:
        fh.write('#include "stm32v8xx.h"\n')
    sys.stderr.write('wrote %s (%d peripherals, %d interrupts)\n'
                     % (path, len(emitted), len(irqs)))


if __name__ == '__main__':
    main()
