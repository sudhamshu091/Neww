Reverse Engineering CryptoWallet.apk to Find Encryption Algorithm with Ghidra

Unpack APK: Use APKTool to extract classes.dex and check for native libraries (e.g., libwallet.so).
Decompile Java: Use JADX to view Java code, search for encrypt or crypto to spot encryption clues.
Set Up Ghidra: Create a new project, import classes.dex and libwallet.so (ARMv7 architecture).
Check Java Code: In Ghidra, find encryptKey in com.cryptowallet.security.KeyProtector; note it’s a native call.
Analyze Native Code: Locate Java_com_cryptowallet_security_KeyProtector_encryptKey in libwallet.so, find custom_encrypt function.
Identify Algorithm: Discover custom_encrypt uses a custom XOR cipher with a key from PIN XORed with 0x5A.
Confirm Findings: Verify no standard crypto (e.g., AES) is used; the XOR cipher is the primary encryption.
Result: The app uses a weak custom XOR cipher with a PIN-based key.
