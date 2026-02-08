# Detecting competitor botnet cleanup with auditd

[Mirai variants](https://shadowshell.io/mirai-sora-botnet) actively compete for control of infected devices. In SORA's source code, `mw_init_killer` iterates through `/proc`, reads the `/proc/[pid]/exe` symlink for each running process and checks if the path contains `.anime` (a marker for the rival Anime botnet). If it finds a match, it deletes the binary (`unlink`) and kills the process with `SIGKILL`. With `auditd`, we can detect the deletion step by watching for `unlink`/`unlinkat` syscalls where the path contains `.anime`. Since `auditd` logs the syscall and the file path as separate records sharing the same event ID, detection either relies correlation at the SIEM level.

First, we need to log file deletions:

```
$ auditctl -a always,exit -S unlink -S unlinkat -k delete
```

Then, we can filter the logs via Sigma. The record types and fields can be found [here](https://access.redhat.com/articles/4409591).

```yml
# Rule 1: unlink syscalls
title: Auditd - unlink/unlinkat syscall
logsource:
  product: linux
  service: auditd
detection:
  selection:
    type: SYSCALL
    syscall:
      - unlink
      - unlinkat
  condition: selection
```

```yml
# Rule 2: .anime in path
title: Auditd - .anime file path
logsource:
  product: linux
  service: auditd
detection:
  selection:
    type: PATH
    name|contains: ".anime"
  condition: selection
```
