/************ AES-Dumper-Darwin **************/
/************* Ragekill3377 ******************/

// Credits to: @facebook for fishhook
//             @Aethereux for the idea (I implemented this after a few weeks, lol)
//             @mmozeiko for aes-finder

// dump.c

// Relevant Docs:
// https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man3/CCCrypt.3cc.html
// https://github.com/xybp888/iOS-SDKs/blob/4c6806ebec5353f202a8e39dafba158d52f057e4/iPhoneOS18.1.sdk/usr/include/CommonCrypto/CommonCryptor.h
// https://github.com/xybp888/iOS-SDKs/blob/4c6806ebec5353f202a8e39dafba158d52f057e4/iPhoneOS18.1.sdk/usr/include/CommonCrypto/CommonKeyDerivation.h#L96

/*
This program aims to demonstrate how attackers could extract AES
Keys at runtime, even if you wipe the keys or obfuscate them.
This is a PoC, not yet tested.

Do not use this for malicious purposes.
Educational Purposes only.

This tool also uses fishhook by @facebook for hooking purposes.
Instead of scanning over the memory and looking for wildcards,
this utility directly hooks the CommonCryptor functions to extract
AES keys (and IVs if available.)
*/

#include <stdio.h>
#include <dlfcn.h>
#include <string.h>
#include <CommonCrypto/CommonCryptor.h>
#include <CommonCrypto/CommonKeyDerivation.h>
#include <Security/Security.h>
#include <os/log.h> // since im doing all this in C, i'll use ``os_log``
#include "fishhook/fishhook.h"

typedef CCCryptorStatus (*CCCryptFunc)(CCOperation, CCAlgorithm, CCOptions, const void *, size_t, const void *, const void *, size_t, void *, size_t, size_t *);
typedef CCCryptorStatus (*CCCryptorCreateWithModeFunc)(CCOperation, CCMode, CCAlgorithm, CCPadding, const void *, const void *, size_t, const void *, size_t, size_t, CCModeOptions, CCCryptorRef *);
typedef CFTypeRef (*SecKeyCreateWithDataFunc)(CFDataRef, CFDictionaryRef, CFErrorRef *);

static CCCryptFunc orig_CCCrypt = NULL;
static CCCryptorCreateWithModeFunc orig_CCCryptorCreateWithMode = NULL;
static SecKeyCreateWithDataFunc orig_SecKeyCreateWithData = NULL;

// 512 bytes of a buffer -> hex str
// this is all C so no std::hex
static void hex_dump(const char *title, const void *buf, size_t len) {
    char out[1025] = {0};
    size_t cc, max = len < 512 ? len : 512;
    for (cc = 0; cc < max && cc * 2 + 1 < sizeof(out); cc++) {
    sprintf(out + cc * 2, "%02x", ((const unsigned char *)buf)[cc]);
    }
    os_log(OS_LOG_DEFAULT, "%s (%lu): %s", title, len, out);
}

/* CRYPTO KIT SHIT START*/
typedef int (*CCKeyDerivationPBKDFFunc)(
    CCPBKDFAlgorithm algorithm,
    const char *password, size_t passwordLen,
    const uint8_t *salt, size_t saltLen,
    CCPseudoRandomAlgorithm prf,
    uint rounds,
    uint8_t *derivedKey, size_t derivedKeyLen
);

static CCKeyDerivationPBKDFFunc orig_CCKeyDerivationPBKDF = NULL;

int my_CCKeyDerivationPBKDF(
    CCPBKDFAlgorithm algorithm,
    const char *password, size_t passwordLen,
    const uint8_t *salt, size_t saltLen,
    CCPseudoRandomAlgorithm prf,
    uint rounds,
    uint8_t *derivedKey, size_t derivedKeyLen
) {
    os_log(OS_LOG_DEFAULT, "[CCKeyDerivationPBKDF]");
    hex_dump("Password", password, passwordLen);
    hex_dump("Salt", salt, saltLen);
    os_log(OS_LOG_DEFAULT, "Rounds (times/loops): %u, length of key: %zu", rounds, derivedKeyLen);
    int result = orig_CCKeyDerivationPBKDF(algorithm, password, passwordLen, salt, saltLen, prf, rounds, derivedKey, derivedKeyLen);
    if (result == kCCSuccess) {
    hex_dump("DerivedKey", derivedKey, derivedKeyLen);
    } else {
    os_log(OS_LOG_DEFAULT, "key derivation failed for some reason, err code: %d", result);
    }
    return result;
}
/* CRYPTO KIT SHIT END */

// kCCBlockSizeAES128 is always 16 bytes, no matter AES type i.e 128, 192, 256 etc have the same block size
// as the key would be passed at bytes, we use ``hex_dump`` to conv those bytes -> hex
CCCryptorStatus my_CCCrypt(CCOperation op, CCAlgorithm alg, CCOptions options, const void *key, size_t keylen, const void *iv, const void *datain, size_t datainlen, void *outdata, size_t outdataavilable, size_t *outdatamoved) {
    os_log(OS_LOG_DEFAULT, "[CCCrypt]");
    hex_dump("Key", key, keylen);
    if (iv) hex_dump("IV", iv, kCCBlockSizeAES128); // optional
    return orig_CCCrypt(op, alg, options, key, keylen, iv, datain, datainlen, outdata, outdataavilable, outdatamoved);
}

// https://github.com/xybp888/iOS-SDKs/blob/4c6806ebec5353f202a8e39dafba158d52f057e4/iPhoneOS18.1.sdk/usr/include/CommonCrypto/CommonCryptor.h#L744
CCCryptorStatus my_CCCryptorCreateWithMode(CCOperation op, CCMode mode, CCAlgorithm alg, CCPadding padding, const void *iv, const void *key, size_t keylen, const void *tweak, size_t tweaklength, int numrounds, CCModeOptions options, CCCryptorRef *cryptorRef) {
    os_log(OS_LOG_DEFAULT, "[CCCryptorCreateWithMode]");
    hex_dump("Key", key, keylen);
    if (iv) hex_dump("IV", iv, kCCBlockSizeAES128); // optional
    return orig_CCCryptorCreateWithMode(op, mode, alg, padding, iv, key, keylen, tweak, tweaklength, numrounds, options, cryptorRef);
}

CFTypeRef my_SecKeyCreateWithData(CFDataRef keydata, CFDictionaryRef attrs, CFErrorRef *error) {
    os_log(OS_LOG_DEFAULT, "[SecKeyCreateWithData]");
    const UInt8 *bytes = CFDataGetBytePtr(keydata);
    CFIndex len = CFDataGetLength(keydata);
    hex_dump("SecKey", bytes, len);
    return orig_SecKeyCreateWithData(keydata, attrs, error);
}

__attribute__((constructor))
static void init() {
    os_log(OS_LOG_DEFAULT, "[+] AES-Dumper Loaded");
    rebind_symbols((struct rebinding[]){
        {"CCCrypt", (void *)my_CCCrypt, (void **)&orig_CCCrypt},
        {"CCCryptorCreateWithMode", (void *)my_CCCryptorCreateWithMode, (void **)&orig_CCCryptorCreateWithMode},
        {"SecKeyCreateWithData", (void *)my_SecKeyCreateWithData, (void **)&orig_SecKeyCreateWithData},
        {"CCKeyDerivationPBKDF", (void *)my_CCKeyDerivationPBKDF, (void **)&orig_CCKeyDerivationPBKDF}
    }, 4);
}
/* Supports all AES forms (128, 192, 256 etc.) */
/* PRs are open                                */
/* Any recommendations are welcome             */