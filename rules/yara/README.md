# YARA Rules

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
PRs must include family name + reference.
