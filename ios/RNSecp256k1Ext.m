//
//  RNSecp256k1Ext.c
//  RNSecp256k1
//
//  Created by 刘宇钧 on 2018/12/27.
//  Copyright © 2018 liuyujun. All rights reserved.
//

#import <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonCryptor.h>
#include "RNSecp256k1Ext.h"

#include "base64.h"

@implementation RNSecp256k1Ext


- (dispatch_queue_t)methodQueue
{
    return dispatch_get_main_queue();
}
+ (BOOL)requiresMainQueueSetup
{
    return YES;
}
RCT_EXPORT_MODULE()


RCT_EXPORT_METHOD(generateKey:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject) {
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        unsigned char rawPriv[32];
        do {
            int result = SecRandomCopyBytes(kSecRandomDefault, sizeof(rawPriv), rawPriv);
            if(result != 0) {
                NSLog(@"SecRandomCopyBytes failed for some reason");
                for (int i = 0; i < sizeof(rawPriv); i++) {
                    rawPriv[i] = (uint8_t)rand();
                }
            }
        } while (!secp256k1_ec_seckey_verify(kSecp256k1Context, rawPriv));
        
        resolveBase64(resolve, rawPriv, sizeof(rawPriv));
    });
}

void ccc(bool encrypt, NSString *priv, NSString *pub, NSString *data, RCTPromiseResolveBlock resolve, RCTPromiseRejectBlock reject) {
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        unsigned char ecdh[32];
        NSString *err = generateECDH(pub, priv, ecdh);
        if (err != nil) {
            reject(@"Error", err, nil);
        }
        NSData *utf8 = [data dataUsingEncoding:NSUTF8StringEncoding];
        const void *raw;
        size_t rawLen;
        if (encrypt) {
            raw = [utf8 bytes];
            rawLen = [utf8 length];
        } else {
            raw = malloc(from_base64_max_len([utf8 length]));
            rawLen = from_base64([utf8 bytes], [utf8 length], (void *)raw);
        }
        
        CCCryptorRef crypto = nil;
        CCCryptorStatus status = CCCryptorCreate(encrypt ? kCCEncrypt : kCCDecrypt, kCCAlgorithmAES, kCCOptionPKCS7Padding | kCCOptionECBMode,
                                                         ecdh, sizeof(ecdh), NULL, &crypto);
        if (status != kCCSuccess) {
            if (!encrypt) free((void *)raw);
            if (crypto != nil) CCCryptorRelease(crypto);
            reject(@"Error", [NSString stringWithFormat:@"cryptor create error: %d", (int)status], nil);
            return;
        }
        size_t outLen = CCCryptorGetOutputLength(crypto, rawLen, true);
        size_t updateLen = 0;
        size_t finalLen = 0;
        char *out = malloc(outLen + 1);
        status = CCCryptorUpdate(crypto, raw, rawLen, out, outLen, &updateLen);
        if (status != kCCSuccess) {
            if (!encrypt) free((void *)raw);
            CCCryptorRelease(crypto);
            free(out);
            reject(@"Error", [NSString stringWithFormat:@"cryptor update error: %d", (int)status], nil);
            return;
        }
        status = CCCryptorFinal(crypto, out + updateLen, outLen - updateLen, &finalLen);
        if (status != kCCSuccess) {
            if (!encrypt) free((void *)raw);
            CCCryptorRelease(crypto);
            free(out);
            reject(@"Error", [NSString stringWithFormat:@"cryptor final error: %d", (int)status], nil);
            return;
        }
        if (encrypt) {
            resolveBase64(resolve, out, updateLen + finalLen);
        } else {
            out[updateLen + finalLen] = 0;
            resolve([NSString stringWithUTF8String:out]);
        }
        if (!encrypt) free((void *)raw);
        CCCryptorRelease(crypto);
        free(out);
    });
}

RCT_EXPORT_METHOD(encryptECDH:(NSString *)priv pub:(NSString *)pub data:(NSString *)data resolve:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject) {
    ccc(true, priv, pub, data, resolve, reject);
}


RCT_EXPORT_METHOD(decryptECDH:(NSString *)priv pub:(NSString *)pub data:(NSString *)data resolve:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject) {
    ccc(false, priv, pub, data, resolve, reject);
}
@end

