# YARA Rules

This directory is reserved for reviewed static signatures. **CVDS v0.3 does not load
these files at runtime**, so adding a file here does not change endpoint coverage until a
separately reviewed scanner integration is implemented. Active family metadata belongs in
`../ransomware_families.json`.

Add one file per family: `lockbit.yar`, `akira.yar`

Example:
```yara
rule Ransom_LockBit_Honeypot {
  strings:
    $a = "vssadmin delete shadows" wide ascii
    $b = ".lockbit" wide ascii
  condition:
    2 of them
}
```
PRs must include the family name, an authoritative reference, test fixtures containing no
malware, and a false-positive analysis. Never upload a live sample.
