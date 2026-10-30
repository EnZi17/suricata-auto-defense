# suricata-auto-defense

Ubuntu 24.04 single-VM Suricata IDS with automatic UFW defense.

See [single-VM setup and verification](docs/single_vm_setup.md).

```bash
sudo bash scripts/00_run_all.sh
```

The setup installs an isolated attacker namespace (`10.203.0.2`) and captures
traffic on `suri-host` (`10.203.0.1`).


Alerts are available in eve.json, the defense service journal, and the UFW block log.
See [team responsibilities](docs/team_assignments.md).
