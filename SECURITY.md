# Security

ManifestTrace is a read-only static analysis tool. It never modifies an APK, never installs or runs one, and never touches a device.

## Design choices you can rely on

- Only reads the AndroidManifest.xml bytes already inside the .apk you point it at. It makes no network connections and does not phone home.
- A finding is a statement about what the manifest declares, never a claim that a component is actually exploitable. Confirming real impact needs a human to read the component's code.

## Using this responsibly

If a scan turns up something real in an app you do not own, follow coordinated disclosure (ISO/IEC 29147): report it to the vendor first, give them a reasonable window to fix it, and only publish afterwards, the same process this author's own CVEs were disclosed under. Do not batch-scan apps you have no authorisation to test and publish the results. Do not use this to build anything that exploits a finding rather than reports it.

## Reporting a problem with the tool itself

Please open a private security advisory on GitHub (Security tab, "Report a vulnerability"), or an issue for anything that is not sensitive. Include the output of `manifest-trace --version` and, if you can share it, the APK or its build tool version that triggered the problem.
