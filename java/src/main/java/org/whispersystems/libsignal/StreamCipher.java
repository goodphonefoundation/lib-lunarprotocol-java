package org.whispersystems.libsignal;

import org.whispersystems.libsignal.kdf.CryptoHashes;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/*
Note:
   OutputStream in both encryptFile, decryptFile should be BufferedOutputStream
   Use 256 bit key for file encryption.
**/

public class StreamCipher {

    private final int N = 4; // number megabytes
    private final int MB = 1024 * 1024;
    private final String KEY_TYPE = "AES";
    private final String AES_GCM = "AES/GCM/NoPadding";
    private final int GCM_IV_LENGTH = 12; // GCMParameterSpec IV is 12bytes;
    private final int AAD_LENGTH = 32;
    private final int GCM_TAG = 16;
    private final int ENCRYPT_BUFFER_LEN = (N * MB);
    private final int DECRYPPT_BUFFER_LEN = (N * MB) + GCM_IV_LENGTH + AAD_LENGTH + GCM_TAG;

    private SecureRandom secureRandom = new SecureRandom();
    private CryptoHashes hashes = new CryptoHashes();

    public void encryptFile(BufferedInputStream inputStream, OutputStream outputStream, byte[] secret_key) {
        try {
            Cipher gcmCipher = Cipher.getInstance(AES_GCM);
            SecretKey secretKey = new SecretKeySpec(secret_key, KEY_TYPE);
            byte[] raw_data = null;
            if(inputStream.available() > ENCRYPT_BUFFER_LEN) {
                raw_data = new byte[ENCRYPT_BUFFER_LEN];
                boolean flag = false;
                int read_len = raw_data.length;
                while (inputStream.read(raw_data, 0, read_len) != -1) {
                    byte[] cipher = null;
                    if(flag) cipher = encryptGcmData(gcmCipher, secretKey, getIV(), java.util.Arrays.copyOfRange(raw_data, 0, read_len));
                    else cipher = encryptGcmData(gcmCipher, secretKey, getIV(), raw_data);
                    outputStream.write(cipher);
                    if( (inputStream.available() < raw_data.length) && !flag ) {
                        read_len = inputStream.available();
                        flag=true;
                    }
                }
            }
            else {
                raw_data = new byte[inputStream.available()];
                inputStream.read(raw_data, 0, inputStream.available());
                outputStream.write(encryptGcmData(gcmCipher, secretKey, getIV(), raw_data));
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void encryptFileAad(BufferedInputStream inputStream, OutputStream outputStream, byte[] secret_key) {
        try {
            Cipher gcmCipher = Cipher.getInstance(AES_GCM);
            SecretKey secretKey = new SecretKeySpec(secret_key, KEY_TYPE);
            byte[] raw_data = null;
            if(inputStream.available() > ENCRYPT_BUFFER_LEN) {
                raw_data = new byte[ENCRYPT_BUFFER_LEN];
                boolean flag = false;
                int read_len = raw_data.length;
                while (inputStream.read(raw_data, 0, read_len) != -1) {
                    byte[] cipher = null;
                    if(flag) cipher = encryptGcmDataAad(gcmCipher, secretKey, getIV(), getAAD(), java.util.Arrays.copyOfRange(raw_data, 0, read_len));
                    else cipher = encryptGcmDataAad(gcmCipher, secretKey, getIV(), getAAD(), raw_data);
                    outputStream.write(cipher);
                    if( (inputStream.available() < raw_data.length) && !flag ) {
                        read_len = inputStream.available();
                        flag=true;
                    }
                }
            }
            else {
                raw_data = new byte[inputStream.available()];
                inputStream.read(raw_data, 0, inputStream.available());
                outputStream.write(encryptGcmDataAad(gcmCipher, secretKey, getIV(), getAAD(), raw_data));
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void decryptFile(BufferedInputStream inputStream, OutputStream outputStream, byte[] secret_key){
        try {
            Cipher gcmCipher = Cipher.getInstance(AES_GCM);
            SecretKey secretKey = new SecretKeySpec(secret_key, KEY_TYPE);
            byte[] cipher_data = null;
            if(inputStream.available() > DECRYPPT_BUFFER_LEN) {
                cipher_data = new byte[DECRYPPT_BUFFER_LEN];
                boolean flag = false;
                int read_len = cipher_data.length;
                while (inputStream.read(cipher_data, 0, read_len) != -1) {
                    byte[] data = null;
                    if(flag) data = decryptGcmData(gcmCipher, secretKey, java.util.Arrays.copyOfRange(cipher_data, 0, read_len));
                    else data = decryptGcmData(gcmCipher, secretKey, cipher_data);
                    outputStream.write(data);
                    if( (inputStream.available() < cipher_data.length) && !flag ) {
                        read_len = inputStream.available();
                        flag=true;
                    }
                }
            }
            else {
                cipher_data = new byte[inputStream.available()];
                while (inputStream.read(cipher_data) != -1) {
                    outputStream.write(decryptGcmData(gcmCipher, secretKey, cipher_data));
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void decryptFileAad(BufferedInputStream inputStream, OutputStream outputStream, byte[] secret_key){
        try {
            Cipher gcmCipher = Cipher.getInstance(AES_GCM);
            SecretKey secretKey = new SecretKeySpec(secret_key, KEY_TYPE);
            byte[] cipher_data = null;
            if(inputStream.available() > DECRYPPT_BUFFER_LEN) {
                cipher_data = new byte[DECRYPPT_BUFFER_LEN];
                boolean flag = false;
                int read_len = cipher_data.length;
                while (inputStream.read(cipher_data, 0, read_len) != -1) {
                    byte[] data = null;
                    if(flag) data = decryptGcmDataAad(gcmCipher, secretKey, java.util.Arrays.copyOfRange(cipher_data, 0, read_len));
                    else data = decryptGcmDataAad(gcmCipher, secretKey, cipher_data);
                    outputStream.write(data);
                    if( (inputStream.available() < cipher_data.length) && !flag ) {
                        read_len = inputStream.available();
                        flag=true;
                    }
                }
            }
            else {
                cipher_data = new byte[inputStream.available()];
                while (inputStream.read(cipher_data) != -1) {
                    outputStream.write(decryptGcmDataAad(gcmCipher, secretKey, cipher_data));
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private byte[] encryptGcmData(Cipher GcmCipher, SecretKey Key, byte[] GcmIv, byte[] data) throws Exception {
        GCMParameterSpec parameterSpec = new GCMParameterSpec(128, GcmIv);
        GcmCipher.init(Cipher.ENCRYPT_MODE, Key, parameterSpec);
        byte[] cipherData = GcmCipher.doFinal(data);
        ByteBuffer cipherBuffer = ByteBuffer.allocate(GCM_IV_LENGTH + cipherData.length);
        cipherBuffer.put(GcmIv); //GCM_IV_LENGTH=12bytes
        cipherBuffer.put(cipherData); //data cipher
        return cipherBuffer.array(); //{IV|cipher}={12bytes|N*MB}
    }

    private byte[] decryptGcmData(Cipher GcmCipher, SecretKey Key, byte[] cipher_data) throws Exception {
        AlgorithmParameterSpec gcmIv = new GCMParameterSpec(128, cipher_data, 0, GCM_IV_LENGTH);
        GcmCipher.init(Cipher.DECRYPT_MODE, Key, gcmIv);
        byte[] cip = java.util.Arrays.copyOfRange(cipher_data, GCM_IV_LENGTH, cipher_data.length);
        return GcmCipher.doFinal(cip);
    }

    /* Note:
    encryptGcmDataAad expects AAD. It assumes that AAD is not null. Otherwise IllegalArgumentException will be thrown !
    * */
    private byte[] encryptGcmDataAad(Cipher GcmCipher, SecretKey Key, byte[] GcmIv, byte[] AAD, byte[] data) throws Exception {
        GCMParameterSpec parameterSpec = new GCMParameterSpec(128, GcmIv);
        GcmCipher.init(Cipher.ENCRYPT_MODE, Key, parameterSpec);
        GcmCipher.updateAAD(AAD);
        byte[] cipherData = GcmCipher.doFinal(data);
        ByteBuffer cipherBuffer = ByteBuffer.allocate(GCM_IV_LENGTH + AAD_LENGTH + cipherData.length);
        cipherBuffer.put(GcmIv); //GCM_IV_LENGTH = 12 bytes
        cipherBuffer.put(AAD); // AAD = 32 bytes
        cipherBuffer.put(cipherData); //data cipher
        return cipherBuffer.array(); //{IV|cipher}={12 bytes|32 bytes|N*MB}
    }

    private byte[] decryptGcmDataAad(Cipher GcmCipher, SecretKey Key, byte[] cipher_data) throws Exception {
        AlgorithmParameterSpec gcmIv = new GCMParameterSpec(128, cipher_data, 0, GCM_IV_LENGTH);
        GcmCipher.init(Cipher.DECRYPT_MODE, Key, gcmIv);
        byte[] aad = java.util.Arrays.copyOfRange(cipher_data, GCM_IV_LENGTH, GCM_IV_LENGTH + AAD_LENGTH);
        byte[] cip = Arrays.copyOfRange(cipher_data, GCM_IV_LENGTH + AAD_LENGTH, cipher_data.length);
        GcmCipher.updateAAD(aad);
        return GcmCipher.doFinal(cip);
    }

    private byte[] getIV() throws GeneralSecurityException{
        byte[] iv = new byte[GCM_IV_LENGTH];
        secureRandom.nextBytes(iv);
        hashes.getDigest(iv, hashes.BLAKE2s256);
        return iv;
    }

    private byte[] getAAD() throws GeneralSecurityException{
        byte[] aad = new byte[AAD_LENGTH];
        secureRandom.nextBytes(aad);
        hashes.getDigest(aad, hashes.SHA3L256);
        return aad;
    }
}