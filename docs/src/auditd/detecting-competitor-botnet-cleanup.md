# Detecting competitor botnet cleanup with auditd

[Mirai variants](https://shadowshell.io/mirai-sora-botnet) actively compete for control of infected devices. In SORA's source code, `mw_init_killer` iterates through `/proc`, reads the `/proc/[pid]/exe` symlink for each running process and checks if the path contains `.anime` (a marker for the rival Anime botnet). If it finds a match, it deletes the binary (`unlink`) and kills the process with `SIGKILL`. With `auditd`, we can detect the deletion step by watching for `unlink`/`unlinkat` syscalls where the path contains `.anime`. Since `auditd` logs the syscall and the file path as separate records sharing the same event ID, detection relies on correlation at the SIEM level.

First, we need to log file deletions:

```
$ sudo auditctl -D
$ sudo auditctl -a always,exit -S unlink -S unlinkat -k delete
```

Test the rule:

```
$ touch .anime
$ rm .anime
$ sudo tail -f /var/log/audit/audit.log
...
type=SYSCALL msg=audit(1770665675.730:2022): arch=c000003e syscall=263 success=yes exit=0 a0=ffffff9c a1=562a95d7e4a0 a2=0 a3=0 items=2 ppid=3194 pid=40941 auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 sgid=1000 fsgid=1000 tty=pts0 ses=3 comm="rm" exe="/usr/bin/rm" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key="delete"ARCH=x86_64 SYSCALL=unlinkat AUID="gemesa" UID="gemesa" GID="gemesa" EUID="gemesa" SUID="gemesa" FSUID="gemesa" EGID="gemesa" SGID="gemesa" FSGID="gemesa"
type=CWD msg=audit(1770665675.730:2022): cwd="/home/gemesa"
type=PATH msg=audit(1770665675.730:2022): item=0 name="/home/gemesa" inode=257 dev=00:20 mode=040700 ouid=1000 ogid=1000 rdev=00:00 obj=unconfined_u:object_r:user_home_dir_t:s0 nametype=PARENT cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 cap_frootid=0OUID="gemesa" OGID="gemesa"
type=PATH msg=audit(1770665675.730:2022): item=1 name=".anime" inode=1318807 dev=00:20 mode=0100644 ouid=1000 ogid=1000 rdev=00:00 obj=unconfined_u:object_r:user_home_t:s0 nametype=DELETE cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 cap_frootid=0OUID="gemesa" OGID="gemesa"
type=PROCTITLE msg=audit(1770665675.730:2022): proctitle=726D002E616E696D65
...
```

Then, we can filter the logs via Sigma. The record types and fields can be found [here](https://access.redhat.com/articles/4409591). In this case, we filter for type `SYSCALL` with field `syscall` (`unlink`/`unlinkat`) and type `PATH` with field `name` (`.anime`).

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
