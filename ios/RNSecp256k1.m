
#import "RNSecp256k1.h"

#include "base64.h"

@implementation RNSecp256k1


secp256k1_context *kSecp256k1Context = nil;

- (dispatch_queue_t)methodQueue
{
    uint8_t seed[32];
    int result = SecRandomCopyBytes(kSecRandomDefault, sizeof(seed), seed);
    if(result != 0) {
        NSLog(@"SecRandomCopyBytes failed for some reason");
        for (int i = 0; i < sizeof(seed); i++) {
            seed[i] = (uint8_t)rand();
        }
    }
    kSecp256k1Context = secp256k1_context_create(SECP256K1_FLAGS_BIT_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    int r = secp256k1_context_randomize(kSecp256k1Context, seed); (void)r;
    return dispatch_get_main_queue();
}
- (NSDictionary *)constantsToExport
{
    return @{ @"isEnabled": @TRUE };
}
+ (BOOL)requiresMainQueueSetup
{
    return YES;
}
RCT_EXPORT_MODULE()


RCT_EXPORT_METHOD(verify:(NSString *)data sig:(NSString *)sig pub:(NSString *)pub resolve:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject) {
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        unsigned char rawData[kMaxBufferLength];
        unsigned char rawSig[kMaxBufferLength];
        unsigned char rawPub[kMaxBufferLength];
        size_t rawDataLen = decode_base64(data, rawData);
        size_t rawSigLen = decode_base64(sig, rawSig);
        size_t rawPubLen = decode_base64(pub, rawPub);
        if (rawDataLen != 32 || rawSigLen == 0 || rawPubLen == 0) {
            reject(@"Error", @"Data or Sig or Pubkey invalid", nil);
            return;
        }
        
        secp256k1_ecdsa_signature sig;
        secp256k1_pubkey pubkey;
        if (!secp256k1_ecdsa_signature_parse_der(kSecp256k1Context, &sig, rawSig, rawSigLen)) {
            reject(@"Error", @"signature invalid", nil);
            return;
        }
        if (!secp256k1_ec_pubkey_parse(kSecp256k1Context, &pubkey, rawPub, rawPubLen)) {
            reject(@"Error", @"pubkey invalid", nil);
            return;
        }
        int r = secp256k1_ecdsa_verify(kSecp256k1Context, &sig, rawData, &pubkey);
        resolve([NSNumber numberWithInt:r]);
    });
}

RCT_EXPORT_METHOD(sign:(NSString *)data priv:(NSString *)priv  resolve:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject) {
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        unsigned char rawData[kMaxBufferLength];
        unsigned char rawPriv[kMaxBufferLength];
        size_t rawDataLen = decode_base64(data, rawData);
        size_t rawPrivLen = decode_base64(priv, rawPriv);
        if (rawDataLen != 32 || rawPrivLen != 32) {
            reject(@"Error", @"Data or Key invalid", nil);
            return;
        }
        secp256k1_ecdsa_signature sig;
        if (!secp256k1_ecdsa_sign(kSecp256k1Context, &sig, rawData, rawPriv, NULL, NULL)) {
            resolve(@"");
            return;
        }
        unsigned char rawSig[72];
        size_t rawSigLen = 72;
        secp256k1_ecdsa_signature_serialize_der(kSecp256k1Context, rawSig, &rawSigLen, &sig );
        
        resolveBase64(resolve, rawSig, rawSigLen);
    });
}

RCT_EXPORT_METHOD(secKeyVerify:(NSString *)priv resolve:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject) {
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        unsigned char rawPriv[kMaxBufferLength];
        size_t rawPrivLen = decode_base64(priv, rawPriv);
        if (rawPrivLen != 32) {
            reject(@"Error", @"Key invalid", nil);
            return;
        }
        int r = secp256k1_ec_seckey_verify(kSecp256k1Context, rawPriv);
        resolve([NSNumber numberWithInt:r]);
    });
}


RCT_EXPORT_METHOD(computePubkey:(NSString *)priv compress:(BOOL)compress  resolve:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject) {
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        unsigned char rawPriv[kMaxBufferLength];
        size_t rawPrivLen = decode_base64(priv, rawPriv);
        if (rawPrivLen != 32) {
            reject(@"Error", @"Key invalid", nil);
            return;
        }
        secp256k1_pubkey pubkey;
        if (!secp256k1_ec_pubkey_create(kSecp256k1Context, &pubkey, rawPriv)) {
            resolve(@"");
            return;
        }
        unsigned char rawPub[65];
        size_t rawPubLen = 65;
        unsigned int flags = compress ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED;
        secp256k1_ec_pubkey_serialize(kSecp256k1Context, rawPub, &rawPubLen, &pubkey, flags);
        
        resolveBase64(resolve, rawPub, rawPubLen);
    });
}

RCT_EXPORT_METHOD(privKeyTweakAdd:(NSString *)priv data:(NSString *)data resolve:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject) {
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        unsigned char rawData[kMaxBufferLength];
        unsigned char rawPriv[kMaxBufferLength];
        size_t rawDataLen = decode_base64(data, rawData);
        size_t rawPrivLen = decode_base64(priv, rawPriv);
        if (rawDataLen != 32 || rawPrivLen != 32) {
            reject(@"Error", @"Priv or Data invalid", nil);
            return;
        }
        int r = secp256k1_ec_privkey_tweak_add(kSecp256k1Context, rawPriv, rawData);
        (void)r;
        
        resolveBase64(resolve, rawPriv, rawPrivLen);
    });
}

RCT_EXPORT_METHOD(privKeyTweakMul:(NSString *)priv data:(NSString *)data resolve:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject) {
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        unsigned char rawData[kMaxBufferLength];
        unsigned char rawPriv[kMaxBufferLength];
        size_t rawDataLen = decode_base64(data, rawData);
        size_t rawPrivLen = decode_base64(priv, rawPriv);
        if (rawDataLen != 32 || rawPrivLen != 32) {
            reject(@"Error", @"Priv or Data invalid", nil);
            return;
        }
        int r = secp256k1_ec_privkey_tweak_mul(kSecp256k1Context, rawPriv, rawData);
        (void)r;
        
        resolveBase64(resolve, rawPriv, rawPrivLen);
    });
}

RCT_EXPORT_METHOD(pubKeyTweakMul:(NSString *)pub data:(NSString *)data resolve:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject) {
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        unsigned char rawData[kMaxBufferLength];
        unsigned char rawPub[kMaxBufferLength];
        size_t rawDataLen = decode_base64(data, rawData);
        size_t rawPubLen = decode_base64(pub, rawPub);
        if (rawDataLen != 32 || rawPubLen == 0) {
            reject(@"Error", @"Priv or Data invalid", nil);
            return;
        }
        secp256k1_pubkey pubkey;
        if (!secp256k1_ec_pubkey_parse(kSecp256k1Context, &pubkey, rawPub, rawPubLen)) {
            reject(@"Error", @"pubkey invalid", nil);
            return;
        }
        int r = secp256k1_ec_pubkey_tweak_mul(kSecp256k1Context, &pubkey, rawData);
        (void)r;
        
        unsigned int flags = rawPubLen == 33 ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED;
        secp256k1_ec_pubkey_serialize(kSecp256k1Context, rawPub, &rawPubLen, &pubkey, flags);
        
        resolveBase64(resolve, rawPub, rawPubLen);
    });
}

RCT_EXPORT_METHOD(pubKeyTweakAdd:(NSString *)pub data:(NSString *)data resolve:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject) {
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        unsigned char rawData[kMaxBufferLength];
        unsigned char rawPub[kMaxBufferLength];
        size_t rawDataLen = decode_base64(data, rawData);
        size_t rawPubLen = decode_base64(pub, rawPub);
        if (rawDataLen != 32 || rawPubLen == 0) {
            reject(@"Error", @"Priv or Data invalid", nil);
            return;
        }
        secp256k1_pubkey pubkey;
        if (!secp256k1_ec_pubkey_parse(kSecp256k1Context, &pubkey, rawPub, rawPubLen)) {
            reject(@"Error", @"pubkey invalid", nil);
            return;
        }
        int r = secp256k1_ec_pubkey_tweak_add(kSecp256k1Context, &pubkey, rawData);
        (void)r;
        
        unsigned int flags = rawPubLen == 33 ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED;
        secp256k1_ec_pubkey_serialize(kSecp256k1Context, rawPub, &rawPubLen, &pubkey, flags);
        
        resolveBase64(resolve, rawPub, rawPubLen);
    });
}

RCT_EXPORT_METHOD(createECDHSecret:(NSString *)priv priv:(NSString *)pub resolve:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject) {
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        unsigned char ecdh[32];
        NSString *err = generateECDH(pub, priv, ecdh);
        if (err != nil) {
            reject(@"Error", err, nil);
        }
        resolveBase64(resolve, ecdh, sizeof(ecdh));
    });
}

@end
  
