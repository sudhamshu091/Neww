The Magisk Play Integrity Fix module works by spoofing hardware attestation results to pass Play Integrity and SafetyNet checks, allowing users to bypass device integrity checks and use apps like Google Pay and Netflix on rooted devices. It achieves this by injecting a "classes.dex" file to modify fields in the android.os.Build class and creating a hook in native code to modify system properties. These modifications are specifically targeted at Google Play Services' DroidGuard (SafetyNet/Play Integrity) service. 
Here's a more detailed breakdown:
Spoofing Hardware Attestation:
The module bypasses the need for legitimate hardware attestation, which verifies if a device is a genuine, trusted device. 
Modifying System Properties:
It alters system properties that Google Play Services uses to determine device integrity, such as the ctsProfileMatch (for SafetyNet) and MEETS_DEVICE_INTEGRITY (for Play Integrity) verdicts. 
Targeted Modification:
The changes are only applied to the GMS (Google Mobile Services) unstable process, ensuring that other parts of the system remain unaffected. 
Customization:
The module allows users to define custom values for spoofed fields in a custom.pif.json file, providing flexibility in configuring the fix. 
Not a Root Hiding Solution:
The module is not designed to hide root access or bypass other app-level detection mechanisms; it focuses on passing Play Integrity checks. 
