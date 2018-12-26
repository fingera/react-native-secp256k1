
#import "RNSecp256k1.h"

#include "secp256k1.h"
#include "secp256k1_ecdh.h"

@implementation RNSecp256k1


static const char BASE64_STANDARD_ENCODE[65] =
"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const unsigned char BASE64_STANDARD_DECODE[256] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x3E,
    0xFF, 0xFF, 0xFF, 0x3F,  // +/
    0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0xFF,
    0xFF, 0xFF, 0x00, 0xFF, 0xFF,  // 0-9 =
    0xFF, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
    0x0A, 0x0B, 0x0C, 0x0D, 0x0E,  // A-O
    0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF,  // P-Z
    0xFF, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23,
    0x24, 0x25, 0x26, 0x27, 0x28,  // a-o
    0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF,  // p-z
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
};

static size_t to_base64_len(size_t buf_size) {
    size_t r = (buf_size / 3) * 4;
    switch (buf_size % 3) {
        case 1:
            r += 2;
            break;
        case 2:
            r += 3;
            break;
        default:
            break;
    }
    return r;
}
static void to_base64(const void *buf, size_t buf_size, char *out) {
    size_t tail_len = buf_size % 3;
    size_t loop_size = buf_size - tail_len;
    const uint8_t *input = (const uint8_t *)buf;
    const char *encode_str = BASE64_STANDARD_ENCODE;
    
    for (size_t i = 0; i < loop_size; i += 3) {
        // 11111111 11111111 11111111
        // 11111122 22223333 33444444
        uint8_t byte1 = input[0] >> 2;
        uint8_t byte2 = ((input[0] & 0x3) << 4) | (input[1] >> 4);
        uint8_t byte3 = ((input[1] & 0xF) << 2) | (input[2] >> 6);
        uint8_t byte4 = input[2] & 0x3F;
        out[0] = encode_str[byte1];
        out[1] = encode_str[byte2];
        out[2] = encode_str[byte3];
        out[3] = encode_str[byte4];
        out += 4;
        input += 3;
    }
    
    if (tail_len) {
        uint8_t byte1 = input[0] >> 2;
        uint8_t byte2 = ((input[0] & 0x3) << 4);
        out[0] = encode_str[byte1];
        if (tail_len == 2) {
            byte2 |= (input[1] >> 4);
            uint8_t byte3 = (input[1] & 0xF) << 2;
            out[1] = encode_str[byte2];
            out[2] = encode_str[byte3];
        } else {
            out[1] = encode_str[byte2];
        }
    }
}
size_t from_base64_max_len(size_t str_len) {
    return ((str_len + 3) / 4) * 3;
}
static size_t from_base64(const char *str, size_t str_len, void *buf) {
    uint8_t byte1, byte2, byte3, byte4;
    size_t tail_len = str_len % 4;
    size_t loop_size = str_len - tail_len;
    const uint8_t *input = (const uint8_t *)str;
    uint8_t *output = (uint8_t *)buf;
    const unsigned char *decode_str = BASE64_STANDARD_DECODE;
    
    for (size_t i = 0; i < loop_size; i += 4) {
        // 11111111 11111111 11111111
        // 11111122 22223333 33444444
        byte1 = decode_str[input[0]];
        byte2 = decode_str[input[1]];
        byte3 = decode_str[input[2]];
        byte4 = decode_str[input[3]];
        
        if (byte1 == 0xFF || byte2 == 0xFF || byte3 == 0xFF || byte4 == 0xFF)
            return output - (uint8_t *)buf;
        
        output[0] = (byte1 << 2) | (byte2 >> 4);
        output[1] = (byte2 << 4) | (byte3 >> 2);
        output[2] = (byte3 << 6) | byte4;
        
        output += 3;
        input += 4;
    }
    
    // 剩余1个字节是不合法的，编码的时候最后一个字节会编成2个字节
    switch (tail_len) {
        case 2:
            byte1 = decode_str[input[0]];
            byte2 = decode_str[input[1]];
            if (byte1 == 0xFF || byte2 == 0xFF) break;
            *output++ = (byte1 << 2) | ((byte2 >> 4) & 0x3);
            break;
        case 3:
            byte1 = decode_str[input[0]];
            byte2 = decode_str[input[1]];
            byte3 = decode_str[input[2]];
            if (byte1 == 0xFF || byte2 == 0xFF || byte3 == 0xFF) break;
            output[0] = (byte1 << 2) | ((byte2 >> 4) & 0x3);
            output[1] = (byte2 << 4) | ((byte3 >> 2) & 0xF);
            output += 2;
            break;
        default:
            break;
    }
    
    return output - (uint8_t *)buf;
}


secp256k1_context *kSecp256k1Context = nil;

- (dispatch_queue_t)methodQueue
{
    kSecp256k1Context = secp256k1_context_create(SECP256K1_FLAGS_BIT_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
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


static const size_t kMaxBufferLength = 4096;

static size_t decode_base64(NSString *str, void *buf) {
    const char *c_str = [str UTF8String];
    size_t c_str_len = strlen(c_str);
    if (from_base64_max_len(c_str_len) > kMaxBufferLength) {
        return 0;
    }
    
    return from_base64(c_str, c_str_len, buf);
}

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
            reject(@"Error", @"sign failure", nil);
            return;
        }
        unsigned char rawSig[72];
        size_t rawSigLen = 72;
        secp256k1_ecdsa_signature_serialize_der(kSecp256k1Context, rawSig, &rawSigLen, &sig );
        char baseSig[256];
        to_base64(rawSig, rawSigLen, baseSig);
        baseSig[to_base64_len(rawSigLen)] = 0;
        resolve([NSString stringWithUTF8String:baseSig]);
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
            reject(@"Error", @"create failure", nil);
            return;
        }
        unsigned char rawPub[65];
        size_t rawPubLen = 65;
        unsigned int flags = compress ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED;
        secp256k1_ec_pubkey_serialize(kSecp256k1Context, rawPub, &rawPubLen, &pubkey, flags);
        char basePub[256];
        to_base64(rawPub, rawPubLen, basePub);
        basePub[to_base64_len(rawPubLen)] = 0;
        resolve([NSString stringWithUTF8String:basePub]);
    });
}

RCT_EXPORT_METHOD(createECDHSecret:(NSString *)priv priv:(NSString *)pub resolve:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject) {
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        unsigned char rawPub[kMaxBufferLength];
        unsigned char rawPriv[kMaxBufferLength];
        size_t rawPubLen = decode_base64(pub, rawPub);
        size_t rawPrivLen = decode_base64(priv, rawPriv);
        if (rawPubLen == 0 || rawPrivLen != 32) {
            reject(@"Error", @"Pub or Key invalid", nil);
            return;
        }
        secp256k1_pubkey pubkey;
        if (!secp256k1_ec_pubkey_parse(kSecp256k1Context, &pubkey, rawPub, rawPubLen)) {
            reject(@"Error", @"pubkey invalid", nil);
            return;
        }
        unsigned char nonce_res[32];
        if (!secp256k1_ecdh(kSecp256k1Context, nonce_res, &pubkey, rawPriv, NULL, NULL)) {
            reject(@"Error", @"generate", nil);
            return;
        }
        char baseSecret[256];
        to_base64(nonce_res, 32, baseSecret);
        baseSecret[to_base64_len(32)] = 0;
        resolve([NSString stringWithUTF8String:baseSecret]);
    });
}

@end
  
