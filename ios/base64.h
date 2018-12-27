//
//  base64.h
//  RNSecp256k1
//
//  Created by 刘宇钧 on 2018/12/27.
//  Copyright © 2018 liuyujun. All rights reserved.
//

#ifndef base64_h
#define base64_h
#if __has_include("RCTBridgeModule.h")
#import "RCTBridgeModule.h"
#else
#import <React/RCTBridgeModule.h>
#endif

#include <stdio.h>
#include <string.h>
#include "secp256k1.h"
#include "secp256k1_ecdh.h"



extern secp256k1_context *kSecp256k1Context;

size_t from_base64_max_len(size_t str_len);
size_t from_base64(const char *str, size_t str_len, void *buf);

size_t to_base64_len(size_t buf_size);
void to_base64(const void *buf, size_t buf_size, char *out);


static const size_t kMaxBufferLength = 4096;

static inline size_t decode_base64(NSString *str, void *buf) {
    const char *c_str = [str UTF8String];
    size_t c_str_len = strlen(c_str);
    if (from_base64_max_len(c_str_len) > kMaxBufferLength) {
        return 0;
    }
    
    return from_base64(c_str, c_str_len, buf);
}

static inline NSString *generateECDH(NSString *pub, NSString *priv, void *ecdh) {
    unsigned char rawPub[kMaxBufferLength];
    unsigned char rawPriv[kMaxBufferLength];
    size_t rawPubLen = decode_base64(pub, rawPub);
    size_t rawPrivLen = decode_base64(priv, rawPriv);
    if (rawPubLen == 0 || rawPrivLen != 32) {
        return @"bad encode";
    }
    secp256k1_pubkey pubkey;
    if (!secp256k1_ec_pubkey_parse(kSecp256k1Context, &pubkey, rawPub, rawPubLen)) {
        return @"pubkey bad";
    }
    if (!secp256k1_ecdh(kSecp256k1Context, ecdh, &pubkey, rawPriv, NULL, NULL)) {
        return @"genetate fail";
    }
    return nil;
}

static inline void resolveBase64(RCTPromiseResolveBlock resolve, void *buffer, size_t size) {
    unsigned char base[to_base64_len(size) + 1];
    to_base64(buffer, size, base);
    base[to_base64_len(size)] = 0;
    resolve([NSString stringWithUTF8String:base]);
}

#endif /* base64_h */
