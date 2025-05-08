
1. App Requirements
Google Play Distribution: Your app must be published on Google Play.

Correct Implementation: The API must be integrated using the official SDKs (Java/Kotlin for Android or Unity).

No Misuse: You must not:

Use the API to discriminate against users in unfair ways.

Share verdicts or signals from the API with third parties, except for backend processing.

2. Developer Requirements
Verified Developer Account: You must have a valid Google Play Console account.

API Key Configuration: Securely configure your API key in the Google Cloud Console and restrict it to your app's package name and SHA-256 signing certificate.

Backend Processing: The response from the API should be sent to your secure backend for verification to avoid exposing sensitive information.

3. Device Integrity Check
You must check and respect:

MEETS_DEVICE_INTEGRITY: Ensures the device is not rooted or tampered.

MEETS_BASIC_INTEGRITY: Allows a wider range, including some emulators and rooted devices.

MEETS_STRONG_INTEGRITY (for selected apps): Indicates unmodified official device with Google-certified OS.

4. Usage Limits
There are daily quota limits. If you need higher limits, you must request them via the Google Play Console.

5. Terms of Use
You must comply with:

Google Play Developer Distribution Agreement

Play Integrity API Terms of Service
