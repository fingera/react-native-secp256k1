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

RCT_EXPORT_METHOD(encryptECDH:(NSString *)priv pub:(NSString *)pub data:(NSString *)data resolve:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject) {
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        unsigned char ecdh[32];
        NSString *err = generateECDH(pub, priv, ecdh);
        if (err != nil) {
            reject(@"Error", err, nil);
        }
        size_t numBytesEncrypted = 0;
        NSData *utf8 = [data dataUsingEncoding:NSUTF8StringEncoding];
        size_t bufferSize = [utf8 length] * 3;
        char *buffer = malloc(bufferSize);
        CCCryptorStatus cryptStatus = CCCrypt(kCCEncrypt, kCCAlgorithmAES,
                                              kCCOptionPKCS7Padding | kCCOptionECBMode,
                                              ecdh, kCCKeySizeAES256,
                                              NULL,
                                              [utf8 bytes], [utf8 length],
                                              buffer, bufferSize,
                                              &numBytesEncrypted);
        if (cryptStatus != kCCSuccess) {
            free(buffer);
            reject(@"Error", [NSString stringWithFormat:@"encrypt error: %d",(int)cryptStatus], nil);
            return;
        }
        resolveBase64(resolve, buffer, numBytesEncrypted);
        free(buffer);
    });
    
}


RCT_EXPORT_METHOD(decryptECDH:(NSString *)priv pub:(NSString *)pub data:(NSString *)data resolve:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject) {
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        unsigned char ecdh[32];
        NSString *err = generateECDH(pub, priv, ecdh);
        if (err != nil) {
            reject(@"Error", err, nil);
        }
        NSData *utf8 = [data dataUsingEncoding:NSUTF8StringEncoding];
        
        char *raw = malloc(from_base64_max_len([utf8 length]));
        size_t rawLen = from_base64([utf8 bytes], [utf8 length], raw);
        
        char *buffer = malloc(rawLen * 2);
        size_t bufferSize = rawLen * 2;
        size_t numBytesEncrypted = 0;
        CCCryptorStatus cryptStatus = CCCrypt(kCCDecrypt, kCCAlgorithmAES,
                                              kCCOptionPKCS7Padding | kCCOptionECBMode,
                                              ecdh, kCCKeySizeAES256,
                                              NULL,
                                              raw, rawLen,
                                              buffer, bufferSize,
                                              &numBytesEncrypted);
        if (cryptStatus != kCCSuccess) {
            free(buffer);
            reject(@"Error", [NSString stringWithFormat:@"decrypt error: %d",(int)cryptStatus], nil);
            return;
        }
        buffer[numBytesEncrypted] = 0;
        resolve([NSString stringWithUTF8String:buffer]);
        free(buffer);
    });
}
@end

