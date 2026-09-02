# Static Analysis in Mobile Security

> *"You cannot secure what you do not understand."*

---

## 📌 Introduction

Mobile applications are among the most pervasive endpoints in modern computing—and among the most actively targeted attack surfaces. An Android application package (`.apk`) is a compressed archive containing multiple layers of abstraction: Dalvik/ART bytecode (`.dex` files), native shared libraries (`.so`), XML resources (`res/`), and configuration manifests (`AndroidManifest.xml`).

**Static Analysis in Mobile Security** focuses on inspecting these application layers without executing code on a live device. By combining static decompilation with targeted dynamic tracing, security auditors can inspect hidden methods, reverse-engineer obfuscated logic, uncover hardcoded API credentials, verify network communication security, and dissect Java Native Interface (JNI) execution paths.

---

## 🎯 Why It Matters

Mobile security assessments require deep visibility into both high-level runtime environments (Java/Kotlin bytecode) and low-level system code (C/C++ native binaries):

* **Surface Attack Surface Mapping:** Uncovering non-exported activities, intent filters, deep links, and misconfigured broadcast receivers inside `AndroidManifest.xml`.
* **Credential & Secret Discovery:** Extracting embedded API tokens, encryption keys, and hardcoded backend URLs hidden within string tables or native memory buffers.
* **JNI & Native Code Inspection:** Analyzing compiled shared objects (`.so`) where developers often move sensitive algorithms (such as key derivation or DRM checks) to evade simple bytecode decompilers.
* **Network Protocol Verification:** Inspecting HTTP/HTTPS client implementations (e.g., `OkHttp`) to ensure proper TLS hostname verification and prevent cleartext data exfiltration.

---

## 🧠 Learning Objectives

Upon completing this project, the following mobile security and reverse-engineering concepts are mastered:

* **Bytecode Decompilation & Disassembly:** Reconstructing Java source code from DEX bytecode using `JADX` and reading Smali assembly instructions via `APKTool`.
* **Manifest & Resource Auditing:** Parsing `AndroidManifest.xml` to evaluate requested permissions, component protection flags (`android:exported`), and embedded string assets.
* **Native Library Analysis via JNI:** Using Ghidra and IDA Pro to reverse-engineer C/C++ binaries (`.so` files) and analyze static/dynamic JNI function registrations (`Java_com_package_Class_method` and `JNI_OnLoad`).
* **Network Protocol Analysis:** Tracking background thread execution and OkHttp client configurations to intercept and analyze JSON telemetry payloads.
* **Algorithmic Optimization:** Identifying computationally heavy recursive or cryptographic bottlenecks in binary code and optimizing them using Dynamic Programming ($O(N)$) and Python/NumPy bindings.
* **Obfuscation Reversing:** Unraveling custom string encoding schemes, name mangling (ProGuard/R8), control-flow flattening, and dynamic class loading mechanisms.

---

## 🛠️ Mobile Security Tooling Matrix

All analyses are performed inside an isolated environment on Kali Linux using the following industry-standard utility suite:

| Tool Category | Tools | Application in Mobile Security |
| --- | --- | --- |
| **Bytecode Decompilers** | JADX, JD-GUI, Dex2jar | Reconstruct Java/Kotlin class structures and methods from `.dex` files. |
| **APK Unpackers** | APKTool | Disassemble APK assets, decode binary XML files, and generate Smali code. |
| **Native Disassemblers** | Ghidra, IDA Pro | Reverse-engineer C/C++ shared libraries (`.so`) and inspect JNI functions. |
| **Dynamic Instrumentation** | Frida, GDB | Hook runtime Java methods and trace native memory operations in real time. |
| **Profiling & Runtime** | Android Studio Profiler, Valgrind | Detect memory leaks, measure execution time, and profile algorithmic complexity. |
| **Automation & Math** | Python 3, NumPy | Script offline constraint solvers, string decoders, and matrix transformations. |

---

## 📂 Repository Layout

```
holbertonschool-mobile_Security/
└── static_analysis_in_mobile_security/
    ├── 0-flag.txt
    ├── 1-flag.txt
    ├── 2-flag.txt
    └── 3-flag.txt

```

---

## ⚡ Technical Tasks & Implementation Details

### Task 0: Android App Security (`APK0`)

* **Objective:** Perform static triage on `APK0.apk` to locate a hidden validation secret or flag without running the application on an active emulator or physical device.
* **Execution & Analysis Workflow:**
1. Unpack the application package and extract resources:
```bash
apktool d APK0.apk -o unpacked_apk0/
jadx -d decompiled_apk0/ APK0.apk

```


2. Inspect `AndroidManifest.xml` to identify the primary entry Activity (`android.intent.action.MAIN`).
3. Audit `res/values/strings.xml` and decompiled Java classes for string manipulation methods, XOR arrays, or hardcoded character arrays.
4. Reverse the validation logic in the target verification function to reconstruct the input flag.


* **Deliverable Path:** `static_analysis_in_mobile_security/0-flag.txt`

---

### Task 1: Device-to-Backend Communication (`APK1`)

* **Objective:** Reverse-engineer `APK1.apk` to analyze how the application constructs network requests, serializes device metadata into JSON format, and transmits telemetry to an obfuscated HTTP backend.
* **Execution & Analysis Workflow:**
1. Decompile `APK1.apk` using JADX and search for OkHttp or HttpURLConnection client instantiations.
2. Locate the obfuscated string table containing the target backend domain and endpoint paths.
3. Trace the JSON serialization routine handling device parameters:
```json
{
  "manufacturer": "Android_Emulator",
  "model": "sdk_gphone_x86",
  "device_id": "SIMULATED_ID_7701"
}

```


4. Reconstruct the full HTTP POST request structure and analyze the server response parsing routine to extract `1-flag.txt`.


* **Deliverable Path:** `static_analysis_in_mobile_security/1-flag.txt`

---

### Task 2: Reverse Engineering & Algorithmic Optimization (`APK2`)

* **Objective:** Analyze `APK2.apk`, pinpoint a computationally inefficient calculation embedded in the validation routine, and implement an optimized offline solver to calculate the valid flag.
* **Algorithmic Complexity & Optimization:**
The decompiled application implements a naive recursive function whose execution time scales exponentially:

$$T_{naive}(n) = T(n-1) + T(n-2) + O(1) \implies O(2^n)$$



By applying **Dynamic Programming (Memoization)**, the time complexity is reduced to linear complexity:

$$T_{optimized}(n) = \sum_{i=1}^{n} O(1) \implies O(n)$$


* **Optimization Script Pattern (Python):**
```python
import numpy as np

def solve_optimized(n, memo={}):
    if n in memo:
        return memo[n]
    if n <= 1:
        return n
    memo[n] = (solve_optimized(n - 1, memo) + solve_optimized(n - 2, memo)) % 0xFFFFFFFF
    return memo[n]

# Compute target value efficiently
target_index = 1048576
result = solve_optimized(target_index)
print(f"Calculated Flag Hash: {hex(result)}")

```


* **Deliverable Path:** `static_analysis_in_mobile_security/2-flag.txt`

---

### Task 3: Static Analysis and Native Libraries (`APK3`)

* **Objective:** Analyze `APK3.apk` to inspect interactions between Java bytecode and a compiled C/C++ shared library (`libnative-lib.so`) via the Java Native Interface (JNI).
* **Execution & Analysis Workflow:**
1. Extract native binary architectures from the APK container:
```bash
unzip APK3.apk "lib/*" -d native_libs/

```


2. Load `libnative-lib.so` into **Ghidra** or **IDA Pro**.
3. Locate JNI exports by searching the symbol table for standard C naming conventions or dynamic registration via `JNI_OnLoad`:
```c
// Static JNI Function Binding Signature
JNIEXPORT jboolean JNICALL
Java_com_example_app_MainActivity_verifyNativeFlag(JNIEnv *env, jobject thiz, jstring input) {
    // Low-level C string comparison & pointer arithmetic
}

```


4. Analyze pointer arithmetic, memory buffers, and key transformation loops within the native function disassembly to retrieve the correct flag.


* **Deliverable Path:** `static_analysis_in_mobile_security/3-flag.txt`

---

## 🔬 Mobile Reverse Engineering Pipeline

```
┌─────────────────────────────────────────────────────────────┐
│                    Target APK File Triage                   │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│              APK Unpacking & Resource Extraction            │
├─────────────────────────────────────────────────────────────┤
│  • APKTool: Decode AndroidManifest.xml & Smali              │
│  • JADX: Decompile .dex files to Java source trees          │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│               Multi-Layer Analysis Decision                 │
└──────────────┬───────────────────────────────┬──────────────┘
               │                               │
               ▼                               ▼
┌──────────────────────────────┐┌──────────────────────────────┐
│     Java / Bytecode Logic    ││     Native Library (.so)     │
├──────────────────────────────┤├──────────────────────────────┤
│ • Permission Auditing        ││ • Ghidra / IDA Pro           │
│ • OkHttp Network Tracing     ││ • JNI Signature Parsing      │
│ • String Unpacking           ││ • C/C++ Buffer Analysis      │
└──────────────┬───────────────┘└──────────────┬───────────────┘
               │                               │
               └───────────────┬───────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│             Algorithmic Optimization & Flag Recovery        │
└─────────────────────────────────────────────────────────────┘

```

---

## 🛡️ Defensive Hardening Matrix

> [!IMPORTANT]
> ### 1. Advanced Bytecode & Native Obfuscation
> 
> 
> Enable R8/ProGuard in release builds (`minifyEnabled true`) and utilize advanced obfuscation tools (e.g., DexGuard, OLLVM) to mangle method names, flatten control flow, and encrypt string constants.
> ### 2. Secure Native Memory & Symbol Stripping
> 
> 
> Strip internal debug symbols from shared object libraries (`strip --strip-debug libnative.so`) during release compilation to prevent simple disassembly in Ghidra or IDA Pro.
> ### 3. Network Security Configuration & Certificate Pinning
> 
> 
> Enforce strict TLS configuration rules inside `res/xml/network_security_config.xml` to disable cleartext traffic (`cleartextTrafficPermitted="false"`) and pin server SSL certificates directly inside the app package.
> ### 4. Runtime Application Self-Protection (RASP)
> 
> 
> Implement active checks to detect root environments, active debuggers (`android.os.Debug.isDebuggerConnected()`), emulator artifacts, and dynamic hooking frameworks (like Frida or Xposed).

---

## ⚠️ Disclaimer

> [!WARNING]
> This repository is maintained strictly for academic research, mobile security education, and authorized reverse-engineering evaluations. Analyzing third-party mobile applications without explicit written authorization from the copyright holder may violate software license agreements and legal frameworks.
