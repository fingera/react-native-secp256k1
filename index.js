
import { NativeModules } from 'react-native';

const { RNSecp256k1 } = NativeModules;


const to_char = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const from_char = [];
for (let i = 0; i < to_char.length; i++) {
  from_char[to_char.charCodeAt(i)] = i;
}

function base64_encode(byteArray) {
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

function base64_decode(str) {
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

console.log(base64_decode("BIS/dWImK71pQAhXSPO+avpSrjFxVRgezjG2Y1HM/6SwjMQ9Y7KFnUaf7hXzHJ7bUyQmbm/QQH6HOC1g/EURrNg"));

RNSecp256k1.base64_decode = base64_decode;
RNSecp256k1.base64_encode = base64_encode;

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
}
RNSecp256k1.raw_computePubkey = async function (priv) {
  const bPriv = base64_encode(priv);
  const bPub = await RNSecp256k1.computePubkey(bPriv);
  return base64_decode(bPub);
}




export default RNSecp256k1;
