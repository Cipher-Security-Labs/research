# Unsafe Device String Handling in SteelSeries GG for macOS

**CVE-2026-39254 and CVE-2026-39255**

**Researcher:** Nir Yehoshua, [Cipher Security Labs](https://ciphersecuritylabs.com)  
**Publication date:** August 2026

### Summary

SteelSeries GG for macOS **v107.0.0** ships `libSSEdevice.dylib`, a native library that processes USB/HID device metadata for SteelSeries Engine. An attacker who can supply malicious or emulated HID metadata may trigger unsafe string handling in that library. This is a local/proximate attack model; a network-remote path was not demonstrated.

Two buffer-overflow issues were identified:

- **CVE-2026-39254:** `DeviceGetDescriptionCx2070x` calls unbounded `sprintf` with format `"%s.ptc"` while ignoring the caller's destination `size`.
- **CVE-2026-39255:** `_dup_wcs` measures wide-string length with `wcslen`, allocates from that measurement, then copies with unbounded `wcscpy`; if the source changes between measure and copy, the allocation is undersized.

The demonstrated effects include heap corruption in CVE-2026-39255 and process crashes under controlled laboratory conditions; code execution was not demonstrated.

SteelSeries reported a security fix in **108.3.0**. Cipher Security Labs independently verified that both vulnerable code paths were remediated in that release (see [Patch Analysis](#patch-analysis)).

### Attack Preconditions

Exploitation requires attacker-influenced HID data to reach the affected device-handling paths. CVE-2026-39255 additionally requires the source contents to change between the length measurement and the subsequent copy.

### CVE-2026-39254

#### Root cause

`CxAudioHidDev20805::DeviceGetDescriptionCx2070x` accepts a destination buffer and `size`, zeroes the buffer with `CheckAndZeroBuffer`, reads up to 100 bytes of device-side data through `ReadMemoryThruRegisters`, then formats with `sprintf` instead of a bounded API:

```c
int CxAudioHidDev20805::DeviceGetDescriptionCx2070x(char *buf, unsigned int size) {
    CheckAndZeroBuffer(buf, size, 1);
    ReadMemoryThruRegisters(..., desc_data, 100);
    sprintf(buf, "%s.ptc", desc_data);   // size not passed to sink
}
```

The sink uses format string `"%s.ptc"`. The function accepts `size` but does not enforce it at the formatting call.

#### Source-to-sink flow

1. USB/HID device metadata
2. IOKit / HID register read path
3. `ReadMemoryThruRegisters(..., desc_data, 100)`
4. `sprintf(buf, "%s.ptc", desc_data)`
5. Out-of-bounds write past the caller-supplied destination when formatted output exceeds the bound

#### Overflow calculation

Modeling `desc_data` as **99 non-NUL bytes** followed by a terminator, `sprintf(buf, "%s.ptc", desc_data)` writes **104 bytes** (99 bytes of `%s` output plus the four-byte `.ptc` suffix). For a modeled 32-byte destination, this produces a **72-byte overrun**. The placement of `buf` (stack, heap, or elsewhere) was not established in vendor runtime.

**What was proven:** unbounded formatting at the sink, ignored `size`, and deterministic overflow arithmetic for a modeled 99-byte string. **What was not proven:** a physical malicious HID device reaching this sink end-to-end in production, or code execution.

### CVE-2026-39255

#### Root cause

`_dup_wcs` duplicates wide strings during HID enumeration:

```c
wchar_t* dup_wcs(const wchar_t* src) {
    size_t len = wcslen(src);
    wchar_t* dst = malloc((len + 1) * sizeof(wchar_t));
    if (dst)
        wcscpy(dst, src);
    return dst;
}
```

Length is measured before allocation, but `wcscpy` copies the current contents of `src` without an explicit bound. If `src` grows after `wcslen` and before `wcscpy`, the heap allocation is too small.

Example under stale-length conditions on the analyzed x86_64 build: `wcslen` observes 4 wchar_t (20-byte allocation with 4-byte `wchar_t`), then `wcscpy` copies a much longer string (~16 KB in lab conditions).

#### Reachability

The helper is exercised during HID device enumeration in the vulnerable library. Lab validation loaded the real `libSSEdevice.dylib`, resolved `_dup_wcs`, and triggered heap corruption through the measure-then-copy sequence under a mutable-source / TOCTOU condition.

#### Runtime evidence

AddressSanitizer reported a **heap-buffer-overflow** with allocation attributed to `**dup_wcs+0x2c`** in the vendor library (20-byte allocation, oversized copy). A controlled race reproducing the stale-length window also caused repeated crashes in the real `_dup_wcs` path.

**What was proven:** the unsafe sequence in vendor code, enumeration reachability, and heap corruption at the vendor allocation site under stale-length conditions. **What was not proven:** end-to-end exploitation from a physical malicious USB device, or overflow from a long but stable HID string alone.

### Patch Analysis

Cipher Security Labs extracted `libSSEdevice.dylib` from SteelSeries GG **108.3.0** and compared it to **107.0.0**.

#### CVE-2026-39254

|                       | v107.0.0   | v108.3.0             |
| --------------------- | ---------- | -------------------- |
| Formatter sink        | `_sprintf` | `_snprintf`          |
| Caller `size` at sink | ignored    | passed to `snprintf` |

Patched logic (simplified):

```text
CheckAndZeroBuffer(buf, size, 1)
ReadMemoryThruRegisters(..., desc_data, 100)
snprintf(buf, size, "%s.ptc", desc_data)
```

The format string `"%s.ptc"` remains; the fix enforces the destination bound at the sink.

#### CVE-2026-39255

|                                         | v107.0.0              | v108.3.0                |
| --------------------------------------- | --------------------- | ----------------------- |
| `_dup_wcs`                              | present               | removed                 |
| `_wcscpy` import                        | present               | removed                 |
| HIDAPI exports used by enumeration path | present in this dylib | removed from this dylib |

### Disclosure Timeline

| Date       | Event                                                                   |
| ---------- | ----------------------------------------------------------------------- |
| 2026-06-10 | Reported to SteelSeries                                                 |
| 2026-06-15 | Technical details shared with SteelSeries                               |
| 2026-07-31 | SteelSeries reported fix in **108.3.0**; CSL verified both remediations |

### Conclusion

Two trust-boundary failures in `libSSEdevice.dylib` allowed device-influenced strings to reach unbounded C runtime sinks: unbounded `sprintf` with an ignored `size` parameter (CVE-2026-39254), and measure-then-copy wide-string duplication with `wcscpy` (CVE-2026-39255). The strongest runtime signal was a vendor-library heap overflow in `_dup_wcs`; CVE-2026-39254 is supported by static analysis and overflow arithmetic at the confirmed sink.

SteelSeries GG **108.3.0** replaces the `_sprintf` path with bounded `snprintf`, and removes `_dup_wcs` and `_wcscpy` from the affected enumeration surface. Users on macOS should update to **108.3.0 or later** from [SteelSeries GG downloads](https://steelseries.com/gg/downloads/gg).

### References

- [https://www.cve.org/CVERecord?id=CVE-2026-39254](https://www.cve.org/CVERecord?id=CVE-2026-39254)
- [https://www.cve.org/CVERecord?id=CVE-2026-39255](https://www.cve.org/CVERecord?id=CVE-2026-39255)
- [https://steelseries.com/gg/downloads/gg](https://steelseries.com/gg/downloads/gg)
- [https://ciphersecuritylabs.com](https://ciphersecuritylabs.com)

### Technical Appendix

Artifact details for independent verification of the analyzed **107.0.0** binary and the patched **108.3.0** build.

#### Binaries

|              | v107.0.0 (vulnerable)                                              | v108.3.0 (patched)                                                 |
| ------------ | ------------------------------------------------------------------ | ------------------------------------------------------------------ |
| Component    | `libSSEdevice.dylib`                                               | `libSSEdevice.dylib`                                               |
| Architecture | Mach-O 64-bit x86_64                                               | Mach-O 64-bit x86_64                                               |
| SHA-256      | `09c7e8e281e1235bd72999c5de8e1494f619aa70dc4bea2486ac6574bc9b2379` | `e5509050de10cac9a6d4f20157b5f38802e5b2376c122814ab27a7f051944282` |

#### CVE-2026-39254 symbols and offsets (v107.0.0)

| Item                   | Value                                                         |
| ---------------------- | ------------------------------------------------------------- |
| Parent dispatch        | `CxAudioHidDevice::DeviceGetDescriptionString` (`0x2f432`)    |
| Vulnerable function    | `CxAudioHidDev20805::DeviceGetDescriptionCx2070x` (`0x11e66`) |
| Vulnerable sink        | `_sprintf` at `0x11f32`                                       |
| Format string          | `"%s.ptc"`                                                    |
| Patched sink (108.3.0) | `_snprintf` at `0x11399`                                      |

#### CVE-2026-39255 symbols and offsets (v107.0.0)

| Item                 | Value                                         |
| -------------------- | --------------------------------------------- |
| Vulnerable function  | `_dup_wcs` (`0x31200`)                        |
| Vulnerable sink      | `_wcscpy` at `0x31239`                        |
| ASAN allocation site | `dup_wcs+0x2c` (`libSSEdevice.dylib+0x3122c`) |
