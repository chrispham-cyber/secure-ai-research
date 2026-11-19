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
