
import { NativeModules } from 'react-native';

const { RNSecp256k1, RNSecp256k1Ext } = NativeModules;


////////////////////////////////////// hex /////////////////////////////////////
function to_hex_value(c) {
  if (c >= 0x30 && c <= 0x39) return c - 0x30;
  if (c >= 0x41 && c <= 0x5A) return (c - 0x41) + 10;
  if (c >= 0x61 && c <= 0x7A) return (c - 0x61) + 10;
  return 0;
}
RNSecp256k1.hex_decode = function (str) {
  const bytes = [];
  let len = str.length;
  if (len % 2 === 1) len--; // ingore single char
  for (let i = 0; i < len; i += 2) {
    const c1 = to_hex_value(str.charCodeAt(i));
    const c2 = to_hex_value(str.charCodeAt(i + 1));
    bytes.push(c2 | (c1 << 4));
  }
  return bytes;
}
const hex_str = "0123456789ABCDEF";

RNSecp256k1.hex_encode = function (bytes) {
  let str = "";
  for (let i = 0; i < bytes.length; i++) {
    const b = bytes[i];
    str += hex_str[b >> 4];
    str += hex_str[b & 0xF];
  }
  return str;
}

//////////////////////////////////// base64 ////////////////////////////////////
const to_char = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const from_char = [];
for (let i = 0; i < to_char.length; i++) {
  from_char[to_char.charCodeAt(i)] = i;
}

RNSecp256k1.base64_encode = function (byteArray) {
  let result = "";
  const tail_len = byteArray.length % 3;
  const chunk_len = byteArray.length - tail_len;
  let i = 0;
  while (i < chunk_len) {
    result += to_char[byteArray[i] >> 2];
    result += to_char[((byteArray[i] & 3) << 4) | (byteArray[i + 1] >> 4)];
    result += to_char[((byteArray[i + 1] & 15) << 2) | (byteArray[i + 2] >> 6)];
    result += to_char[byteArray[i + 2] & 63];
    i += 3;
  }
  if (tail_len) {
    result += to_char[byteArray[i] >> 2];
    if (tail_len === 1) {
      result += to_char[((byteArray[i] & 3) << 4)];
    } else {
      result += to_char[((byteArray[i] & 3) << 4) | (byteArray[i + 1] >> 4)];
      result += to_char[((byteArray[i + 1] & 15) << 2)];
    }
  }
  return result;
}

RNSecp256k1.base64_decode = function (str) {
  const bytes = [];
  let byte1, byte2, byte3, byte4;
  str = str.replace(/[\r\n\t ]/g, "");
  const tail_len = str.length % 4;
  const chunk_len = str.length - tail_len;
  if (tail_len === 1) {
    throw new Error(`bad char ${str} len ${str.length}`);
  }
  let i = 0;
  while (i < chunk_len) {
    byte1 = from_char[str.charCodeAt(i++)];
    byte2 = from_char[str.charCodeAt(i++)];
    byte3 = from_char[str.charCodeAt(i++)];
    byte4 = from_char[str.charCodeAt(i++)];
    if (byte1 === undefined || byte2 === undefined
        || byte3 === undefined || byte4 === undefined) {
      throw new Error(`bad char ${str} ${i}`);
    }
    bytes.push(((byte1 << 2) & 0xFF) | (byte2 >> 4));
    bytes.push(((byte2 << 4) & 0xFF) | (byte3 >> 2));
    bytes.push(((byte3 << 6) & 0xFF) | byte4);
  }
  if (tail_len) {
    byte1 = from_char[str.charCodeAt(i++)];
    byte2 = from_char[str.charCodeAt(i++)];
    if (byte1 === undefined || byte2 === undefined) {
      throw new Error(`bad char ${str} ${i}`);
    }
    bytes.push(((byte1 << 2) & 0xFF) | (byte2 >> 4));
    if (tail_len === 3) {
      byte3 = from_char[str.charCodeAt(i++)];
      if (byte3 === undefined) throw new Error(`bad char ${str} ${i}`);
      bytes.push(((byte2 << 4) & 0xFF) | (byte3 >> 2));
    }
  }
  return bytes;
}

//////////////////////////////// raw interface ////////////////////////////////
RNSecp256k1.raw_verify = async function (data, signature, pub) {
  const bData = base64_encode(data);
  const bSig = base64_encode(signature);
  const bPub = base64_encode(pub);
  return await RNSecp256k1.verify(bData, bSig, bPub);
};
RNSecp256k1.raw_sign = async function (data, priv) {
  const bData = base64_encode(data);
  const bPriv = base64_encode(priv);
  const bSignature = await RNSecp256k1.sign(bData, bPriv);
  return base64_decode(bSignature);
};
RNSecp256k1.raw_secKeyVerify = async function (priv) {
  const bPriv = base64_encode(priv);
  return await RNSecp256k1.secKeyVerify(bPriv);
};
RNSecp256k1.raw_computePubkey = async function (priv, compressed) {
  const bPriv = base64_encode(priv);
  const bPub = await RNSecp256k1.computePubkey(bPriv, compressed ? true : false);
  return base64_decode(bPub);
};
RNSecp256k1.raw_createECDHSecret = async function (priv, pub) {
  const bPriv = base64_encode(priv);
  const bPub = base64_encode(pub);
  const bSecret = await RNSecp256k1.createECDHSecret(bPriv, bPub);
  return base64_decode(bSecret);
};
/*
RNSecp256k1.raw_randomize = async function (random) {
  const bRandom = base64_encode(random);
  return await RNSecp256k1.randomize(bRandom);
};
*/
RNSecp256k1.raw_privKeyTweakMul = async function (priv, tweak) {
  const bPriv = base64_encode(priv);
  const bTweak = base64_encode(tweak);
  const bResult = await RNSecp256k1.privKeyTweakMul(bPriv, bTweak);
  return base64_decode(bResult);
};
RNSecp256k1.raw_privKeyTweakAdd = async function (priv, tweak) {
  const bPriv = base64_encode(priv);
  const bTweak = base64_encode(tweak);
  const bResult = await RNSecp256k1.privKeyTweakAdd(bPriv, bTweak);
  return base64_decode(bResult);
};
RNSecp256k1.raw_pubKeyTweakMul = async function (pub, tweak) {
  const bPub = base64_encode(pub);
  const bTweak = base64_encode(tweak);
  const bResult = await RNSecp256k1.pubKeyTweakMul(bPub, bTweak);
  return base64_decode(bResult);
};
RNSecp256k1.raw_pubKeyTweakAdd = async function (pub, tweak) {
  const bPub = base64_encode(pub);
  const bTweak = base64_encode(tweak);
  const bResult = await RNSecp256k1.pubKeyTweakAdd(bPub, bTweak);
  return base64_decode(bResult);
};

RNSecp256k1.ext = RNSecp256k1Ext;

export default RNSecp256k1;
