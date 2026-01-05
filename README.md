# Micro-Defense-System-for-Param-aware-System-Calls

Micro-Defense System for Parameter-Aware System Calls is a lightweight **user-space security framework** designed to **monitor, analyze, and enforce security policies on Linux system calls based on their parameters**.

Unlike traditional syscall filtering mechanisms that only consider syscall numbers, this project focuses on **parameter-aware syscall inspection**, enabling finer-grained defense against exploitation techniques such as privilege escalation, malicious file access, and abnormal process behavior.

---

## 📌 Motivation

System calls are the only interface between user-space programs and the kernel. Many attacks exploit **legitimate syscalls with malicious parameters** rather than invoking illegal syscalls.

Examples:
- `chmod()` changing permissions of sensitive files
- `connect()` to unexpected network families
- `ptrace()` attaching to non-child processes
- `setuid()` / `setgid()` abuse
- `kill()` signaling unrelated processes

This project aims to:
- Detect **dangerous syscall parameter patterns**
- Enforce **fine-grained security policies**
- Serve as a **research and educational prototype** for syscall-based defense systems

---

## 🧠 Key Features

- 🔍 **Syscall interception using `ptrace`**
- 🧩 **Parameter-level syscall inspection**
- 🛡️ **Policy-based allow / deny decisions**
- 📄 Modular syscall policy files
- 🧪 Test programs for validation
- 🧱 Designed as a micro-defense layer (not a full sandbox)

---

## 📁 Project Structure
Micro-Defense-System-for-Param-aware-System-Calls
├── src/
│ ├── tracer.c # Main tracer logic
│ ├── syscall_decode.c # Syscall decoding
│ ├── syscall_policy/ # Per-syscall policy modules
│ │ ├── 90_chmod.c
│ │ ├── 62_kill.c
│ │ └── ...
│ ├── util.c
│ └── util.h
├── test/
│ ├── victim.c # Sample target program
│ └── scripts/
├── Makefile
├── README.md
└── LICENSE


---

## ⚙️ Requirements

| Component | Requirement |
|--------|-------------|
| OS | Linux (x86_64 recommended) |
| Compiler | GCC / Clang |
| Build Tool | GNU Make |
| Privilege | `sudo` (required for `ptrace`) |

---

## 🛠️ Build

Clone the repository and build:

```bash
git clone https://github.com/ToanNguyen13025/Micro-Defense-System-for-Param-aware-System-Calls.git
cd Micro-Defense-System-for-Param-aware-System-Calls
make
```

The compiled binary will be generated in the project directory.

## ▶️ Usage
Run the tracer with a target program. The tracer will fork a child process, attach to it using `ptrace`, and monitor all system calls issued by the child.

```bash
sudo ./tracer ./test/victim
```

### Example Output

```
Parent PID: 29838, Child PID: 29839
[decode] syscall=62
Syscall 62 args: pid=1234 sig=9
[ALERT] kill(): target is not a child process
```

The output shows:
- The syscall number
- Decoded syscall parameters
- Policy decisions (INFO / ALERT / BLOCK)

---

## 🧩 How It Works

The system operates entirely in user space using `ptrace`:

1. The parent process forks a child
2. The child calls `ptrace(PTRACE_TRACEME)` and executes the target program via `execve`
3. The parent waits for syscall entry/exit events
4. CPU registers are read using `PTRACE_GETREGS`
5. Syscall number and arguments are decoded
6. Parameters (e.g., pointers) are safely read from the child’s memory
7. A syscall-specific policy function is invoked
8. The policy decides whether to:
   - Allow the syscall
   - Log a warning
   - Terminate the child process

---

## 🧪 Example Policies

- **chmod**: Block permission escalation (e.g. mode `0777`)
- **kill**: Only allow signaling child processes
- **connect**: Restrict address families (AF_INET / AF_INET6)
- **ptrace**: Prevent attaching to unrelated processes
- **setuid / setgid**: Deny privilege escalation

Each syscall policy is implemented as an independent C module under `src/syscall_policy/`.

---

## 🎯 Project Scope

This project is intended for:

- Operating Systems coursework
- Linux security research
- Syscall behavior analysis
- Learning `ptrace`-based monitoring
- Proof-of-concept micro defense systems

⚠️ This project is **not** intended to replace production-grade sandboxing solutions such as `seccomp`, `SELinux`, or `AppArmor`.

---

## 🚧 Future Work

- Extend coverage to more syscalls
- Add syscall behavior profiling
- Support learning-based / adaptive policies
- Reduce `ptrace` overhead
- Add structured logging (JSON)
- Container / namespace awareness

---

## 📜 License

This project is licensed under the **MIT License**.

---




