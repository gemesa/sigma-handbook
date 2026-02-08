# `auditd` overview

[`auditd`](https://man7.org/linux/man-pages/man8/auditd.8.html) is Linux's built-in auditing system. You write rules with [`auditctl`](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/security_hardening/auditing-the-system_security-hardening#using-auditctl-for-defining-and-executing-audit-rules_auditing-the-system) and it logs kernel-level events (syscalls, file access, process execution, etc.). It is the go-to for getting visibility into what is actually happening on a Linux box.
