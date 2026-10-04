# Validating a finding

A finding from ManifestTrace is a lead, not proof. Before it means anything to anyone, it needs a human to confirm it, and that process depends entirely on what app you're looking at and whether you're actually authorised to test it. Read this before you do anything with a result.

## The one question that comes first

Do you have clear, documented authorisation to test this specific app?

- Your own app, or a training app built for this purpose (InsecureBankv2, DIVA, and similar): yes, go ahead.
- A third party's app, found through a bug bounty program or an explicit scope you were given: yes, within that scope, and report it through their program.
- Your employer's production app, found incidentally rather than as part of an authorised engagement: no. "I work there" is not the same as "I'm authorised to pentest this." Report the finding to your internal security team and stop there. Let them decide whether and how to validate it.
- Anything else, a random app off the Play Store, a competitor's app, anything you have no relationship to: no. Do not go further than the static scan. If you believe the finding is real and serious, the only responsible next step is coordinated disclosure to the vendor (ISO/IEC 29147), not personal validation first.

If the answer isn't a clear yes, stop at the scan. The scan itself is harmless, it only reads a manifest file already on your disk. Everything past that point is a different kind of action with different consequences.

## If you do have authorisation, how to confirm each check

**exported_without_protection** (an activity, service or receiver)
```bash
adb shell am start -n <package>/<component>
```
If this launches the component directly, bypassing whatever the app's own UI normally requires first, that's confirmation. If the component checks the calling package, a signature, or anything else in its own code before doing anything sensitive, it's a false lead, drop it. ManifestTrace cannot see that code; only reading the component's actual implementation can.

**exported_provider_wide_open**
```bash
adb shell content query --uri content://<authority>/
```
A real response with data confirms it. An error or empty result might mean the provider still enforces something not visible from the manifest.

**allow_backup_enabled**
```bash
adb backup -f backup.ab <package>
```
Then extract it (Android Backup Extractor, or the openssl/dd trick for an unencrypted backup) and look at what actually came out.

**debuggable_true**
```bash
adb shell run-as <package> ls /data/data/<package>
```
If this lists files without root, it's confirmed.

**cleartext_traffic_allowed**
Proxy the app's traffic (mitmproxy, Burp) and watch for a plain `http://` request actually going out. The manifest flag says it's allowed; watching real traffic confirms it's used.

## After you've confirmed something real

If it's your own app or something you're authorised to test: fix it, or report it through the proper internal channel.

If it's someone else's app: coordinated disclosure (ISO/IEC 29147). Report to the vendor's security contact or bug bounty program, give them a reasonable window to fix it before anything goes public, and don't publish exploit details that let someone else act on it before the fix ships. This is the same process this author's own CVE-2025-50861 and CVE-2025-50862 were handled under.

What not to do: scan a large batch of apps you have no relationship to looking for findings to report publicly as a portfolio exercise. A tool finding a lead is not the same as having permission to act on it.
