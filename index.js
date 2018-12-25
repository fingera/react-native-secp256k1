
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
  const tail_len = str.length % 4;
  const chunk_len = str.length - tail_len;
  if (tail_len === 1) {
    throw new Error(`bad char ${str}`);
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
      throw new Error(`bad char ${str}`);
    }
    bytes.push(((byte1 << 2) & 0xFF) | (byte2 >> 4));
    if (tail_len === 3) {
      byte3 = from_char[str.charCodeAt(i++)];
      if (byte3 === undefined) throw new Error(`bad char ${str}`);
      bytes.push(((byte2 << 4) & 0xFF) | (byte3 >> 2));
    }
  }
  return bytes;
}

export default RNSecp256k1;
