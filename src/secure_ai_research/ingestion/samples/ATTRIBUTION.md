# Fixture attribution

`attack_sample.json` is **MITRE ATT&CK®**. © The MITRE Corporation.

This fixture contains a small excerpt of the ATT&CK for Enterprise STIX 2.1 data
(four `attack-pattern` objects: `T1059`, `T1059.001`, `T1566`, and the deprecated
`T1064`), trimmed to the fields this project's loader reads. It is used under the
ATT&CK Terms of Use: <https://attack.mitre.org/resources/legal-and-branding/terms-of-use/>.

Source: <https://github.com/mitre-attack/attack-stix-data> (`enterprise-attack/enterprise-attack.json`).

`nvd_sample.json`, by contrast, is synthetic/fictional test data (not real NVD records).

`kev_sample.json` is a three-entry excerpt of the **CISA Known Exploited
Vulnerabilities (KEV) Catalog** (`CVE-2021-44228`, `CVE-2026-59310`,
`CVE-2024-10441`), each entry kept verbatim from the catalog.

Source: <https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json>
(catalog version 2026.11.18), retrieved 2026-11-19. The CISA KEV catalog is a
work of the U.S. Government and is in the public domain (17 U.S.C. §105);
attribution here is a courtesy, not a license requirement.

`sigma_sample.json` is a two-rule excerpt of **SigmaHQ** detection rules, each kept
verbatim (converted from its upstream YAML to JSON at build time):

- `ca2092a1-c273-4878-9b4b-0d60115bf5ea` — "Suspicious Encoded PowerShell Command Line"
  (`rules/windows/process_creation/proc_creation_win_powershell_base64_encoded_cmd.yml`,
  tagged `attack.t1059.001`);
- `3eb91f0a-0060-424a-a676-59f5fdd75610` — "Potential CVE-2021-44228 Exploitation Attempt -
  VMware Horizon"
  (`rules-emerging-threats/2021/Exploits/CVE-2021-44228/proc_creation_win_exploit_cve_2021_44228_vmware_horizon_log4j.yml`,
  tagged `cve.2021-44228`).

Source: <https://github.com/SigmaHQ/sigma> (`master`), retrieved 2026-11-19. SigmaHQ
rules are licensed under the **Detection Rule License (DRL) 1.1**
(<https://github.com/SigmaHQ/Detection-Rule-License>).
