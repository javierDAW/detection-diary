# PEAK Hunt H2 - DICOM receiver file-write escaping the store, and node/receiver RCE

**Framework:** PEAK (Prepare, Execute, Act with Knowledge) - hypothesis-driven.
**ATT&CK:** T1190 Exploit Public-Facing Application; T1505.003 Server Software Component: Web Shell;
T1059 Command and Scripting Interpreter.

## Hypothesis
An adversary is abusing CVE-2026-50003 (critical, CVSS 9.8) to make a DICOM storage receiver
(storescp / dcmrecv / dcmqrscp) write a file outside its configured incoming directory - a dot-segment
in an attribute-controlled filename escapes the store into a web root or an autostart path, dropping a
web shell or payload. The follow-on is code execution: the receiver, or a web server serving the
written file, spawns a shell. A DICOM store should only ever contain `.dcm` instances.

## Prepare - data sources
- EDR file telemetry: Defender XDR `DeviceFileEvents`, Sysmon EID 11, Linux auditd file writes.
- EDR process telemetry: `DeviceProcessEvents`, Sysmon EID 1, auditd `execve`.
- The DICOM store / incoming directory path for each receiver.

## Execute - logic
1. From `DeviceFileEvents`, keep writes whose `InitiatingProcessFileName` is a DICOM receiver AND whose
   `FileName` ends in a script/executable extension OR whose `FolderPath` contains `..` - see
   `kql/dicom_receiver_file_write.kql` and `sigma/dcmtk_receiver_file_write_traversal.yml`.
2. From `DeviceProcessEvents`, keep any DICOM receiver that is the parent of `cmd`/`powershell`/`bash`
   - see `kql/dcmtk_receiver_shell_spawn.kql` and `sigma/dcmtk_receiver_spawns_shell.yml`.
3. For each file-write hit, resolve where the file landed (web root, cron/systemd, startup) and whether
   it was subsequently read/executed.
4. Pivot both ways: a file write immediately preceding a shell spawn on the same host is the full
   write-to-execute chain.

## Act - triage
- **Confirmed RCE:** a DICOM receiver writing a non-`.dcm` executable/script or a traversal path, and/or
  spawning a shell. Treat the imaging host as compromised; isolate and image.
- **Escalation:** the written file appears in a web-served directory and is then requested over HTTP.
- **Benign:** a vendor pipeline that emits derived reports/thumbnails from the receiver directory;
  confirm the exact extensions and paths against the product documentation and baseline them.

## Knowledge - notes
The durable signal is a DICOM receiver producing anything other than a DICOM instance in its store, or
becoming the parent of an interpreter. Record the output path convention of each receiver so the
traversal/extension anomaly is unambiguous. This chain is the reason a "file write" CVE in an imaging
toolkit is initial-access-to-RCE, not an availability footnote.
