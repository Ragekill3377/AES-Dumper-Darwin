# **AES-Dumper-Darwin** -> **A.D.D**

--------------------------------------------------------------------
This program aims to demonstrate how attackers could extract AES
Keys at runtime, even if you wipe the keys or obfuscate them.
This is a PoC, not yet tested. 

--------------------------------------------------------------------
This tool also uses fishhook by @facebook for hooking purposes.
Instead of scanning over the memory and looking for wildcards,
this utility **directly hooks the CommonCryptor functions to extract
AES keys (and IVs if available.)**

--------------------------------------------------------------------

# **Relevant Docs**:
[Apple Developer Man Page For CommonCrypto](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man3/CCCrypt.3cc.html)
[CC framework header from iOS SDK](https://github.com/xybp888/iOS-SDKs/blob/4c6806ebec5353f202a8e39dafba158d52f057e4/iPhoneOS18.1.sdk/usr/include/CommonCrypto/CommonCryptor.h)

--------------------------------------------------------------------
# **Credits**:
```c
// Credits to: @facebook for fishhook
//             @Aethereux for the idea (I implemented this after a few weeks, lol)
//             @mmozeiko for aes-finder
```
----------------------------------------------------------------------

# **How to protect myself against this?**:
* Anti-Hooking
* Don't use built-in AES frameworks like CommonCrypto
* Use external frameworks such as OpenSSL, Crypto++ etc.
* Hardware backed secure enclave (Although not always available for user apps iirc)
----------------------------------------------------------------------

# **What can this tool bypass?**:
* Encryption/Obfuscation of AES keys will **NOT** help.
* Wiping Keys in Memory **WILL NOT** help.
* Using a wrapper (Swift/Objc), it **WILL** intercept and capture keys.
* Runtime loaded keys, so keys not hard-coded **WILL** be dumped.
* Randomly generated keys **WILL** get caught too
* AES-CBC, AES-ECB, AES-CTR, AES-GCM etc. **WILL** be intercepted
* Tweaked AES modes **DO NOT** offer any advantage.
* "B-But I wrote it i-in S-Swift!" That's just a wrapper for the C functions. CommonCrypto is in C. This **WILL NOT** help.

----------------------------------------------------------------------
# **License**:

----------------------------------------------------------------------
# **Disclaimer**:
```
The developer, Ragekill3377 is NOT responsible for any harmful, malicious or illegal activites in the use of said tool.
Use at your own risk.
This program, if used, should be credited.
For eductional purposes only.
```
----------------------------------------------------------------------

