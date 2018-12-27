package com.reactlibrary;

import android.os.AsyncTask;
import android.util.Base64;

import com.facebook.react.bridge.Promise;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;

import org.bitcoin.NativeSecp256k1;
import org.bitcoin.NativeSecp256k1Util;

import java.io.UnsupportedEncodingException;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class RNSecp256k1Ext extends ReactContextBaseJavaModule {

    private static byte[] Ase(byte[] byteData, byte[] byteKey, int opmode) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        SecretKeySpec skeySpec = new SecretKeySpec(byteKey, "AES");
        cipher.init(opmode, skeySpec);
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

                    byte[] encryped = Ase(data, sec, mode);

                    if (mode == Cipher.ENCRYPT_MODE) {
                        promise.resolve(Base64.encodeToString(encryped, Base64.NO_PADDING | Base64.NO_WRAP));
                    } else {
                        promise.resolve(new String(encryped, "UTF-8"));
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
                    SecureRandom random = new SecureRandom();
                    do {
                        random.nextBytes(privraw);
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
