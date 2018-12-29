package com.reactlibrary;

import android.os.AsyncTask;
import android.util.Base64;

import com.facebook.react.bridge.Promise;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;

import org.bitcoin.NativeSecp256k1;

import java.io.UnsupportedEncodingException;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class RNSecp256k1Ext extends ReactContextBaseJavaModule {
    
    SecureRandom GRandom = new SecureRandom();

    private static byte[] Ase(byte[] byteData, byte[] byteKey, int opmode, IvParameterSpec iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
        SecretKeySpec skeySpec = new SecretKeySpec(byteKey, "AES");
        cipher.init(opmode, skeySpec, iv);
        byte[] decrypted = cipher.doFinal(byteData);
        return decrypted;
    }

    private void AesECDH(final String priv, final String pub, final byte[] data, final int mode, final Promise promise) {
        AsyncTask.execute(new Runnable() {
            @Override
            public void run() {
                try {
                    byte[] privraw = Base64.decode(priv, Base64.NO_PADDING);
                    byte[] pubraw = Base64.decode(pub, Base64.NO_PADDING);
                    byte[] sec = NativeSecp256k1.createECDHSecret(privraw, pubraw);
                    byte[] eData = data;
                    byte[] iv = new byte[]{
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    };
                    IvParameterSpec ivSpec = new IvParameterSpec(iv);
                    if (mode == Cipher.ENCRYPT_MODE) {
                        int paddingLen = 16 - (data.length % 16);
                        if (paddingLen < 2) {
                            paddingLen += 16;
                        }
                        paddingLen--;
                        byte[] random = new byte[paddingLen];
                        GRandom.nextBytes(random);
                        byte[] newData = new byte[random.length + data.length + 1];
                        newData[0] = (byte)paddingLen;
                        System.arraycopy(random, 0, newData, 1, random.length);
                        System.arraycopy(data, 0, newData, 1 + random.length, data.length);
                        eData = newData;
                    }

                    byte[] encryped = Ase(eData, sec, mode, ivSpec);

                    if (mode == Cipher.ENCRYPT_MODE) {
                        promise.resolve(Base64.encodeToString(encryped, Base64.NO_PADDING | Base64.NO_WRAP));
                    } else {
                        // DoUnpadding
                        int dataStart = (int)encryped[0] + 1;
                        int realLen = encryped.length - dataStart;
                        byte[] realData = new byte[realLen];
                        System.arraycopy(encryped, dataStart, realData, 0, realLen);
                        promise.resolve(new String(realData, "UTF-8"));
                    }
                } catch (Exception ex) {
                    ex.printStackTrace();
                    promise.reject("Error", ex.toString());
                }
            }
        });
    }


    public RNSecp256k1Ext(ReactApplicationContext reactContext) {
        super(reactContext);
    }
    @Override
    public String getName() {
        return "RNSecp256k1Ext";
    }

    @ReactMethod
    public void generateKey(final Promise promise) {
        AsyncTask.execute(new Runnable() {
            @Override
            public void run() {
                try {
                    byte[] privraw = new byte[32];
                    do {
                        GRandom.nextBytes(privraw);
                    } while (!NativeSecp256k1.secKeyVerify(privraw));
                    promise.resolve(Base64.encodeToString(privraw, Base64.NO_PADDING | Base64.NO_WRAP));
                } catch (Exception ex) {
                    ex.printStackTrace();
                    promise.reject("Error", ex.toString());
                }
            }
        });
    }

    @ReactMethod
    public void encryptECDH(final String priv, final String pub, final String data, final Promise promise) {
        try {
            AesECDH(priv, pub, data.getBytes("UTF-8"), Cipher.ENCRYPT_MODE, promise);
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
            promise.reject("Error", e.toString());
        }
    }

    @ReactMethod
    public void decryptECDH(final String priv, final String pub, final String data, final Promise promise) {
        AesECDH(priv, pub, Base64.decode(data, Base64.NO_PADDING), Cipher.DECRYPT_MODE, promise);
    }
}
