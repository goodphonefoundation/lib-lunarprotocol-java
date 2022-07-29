package org.whispersystems.libsignal;

import org.whispersystems.libsignal.kdf.CryptoHashes;
import org.whispersystems.libsignal.ratchet.MessageKeys;

import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;


/** GCM Cipher class provides AES-GCM for message encryption/decryption within SessionCipher.
 * It has four different variants with GCM mode to use.
 * Clients can choice GCM variants of encryption/decryption schema.
 * TODO: GCM crypto schema factory for encrypt/decrypt between different variants.
 * */

public class GcmCipher {

    //dtsonov: Do I need constructor call ?
    private SecureRandom secureRandom = new SecureRandom();
    private CryptoHashes hashes = new CryptoHashes();

    /** todo: test: AES-CBC with GCM variant 1:
     * encrypt: AES_CBC(AES_GCM)
     * decrypt: AES_CBC(AES_GCM)
     * */

    public byte[] encrypt_v1(MessageKeys messageKeys, byte[] plaintext) throws Exception {
        //todo: use AAD = messageKeys.getIv() in gcmEncrypt and link to some GCM authentication tag
        //todo: use of the inner GCM authentication tag, as key material to the outer AES-CBC
        try {
            Cipher cipher = getCipher(Cipher.ENCRYPT_MODE, messageKeys.getCipherKey(), messageKeys.getIvSpec());
            return cipher.doFinal( gcmEncrypt(messageKeys.getCipherKey().toString().toCharArray(), plaintext) );
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            throw new AssertionError(e);
        }
    }

    //todo: Verify the GCM auth tag after decrypt !!!
    public byte[] decrypt_v1(MessageKeys messageKeys, byte[] cipherText) throws Exception {
        try {
            Cipher cipher = getCipher(Cipher.DECRYPT_MODE, messageKeys.getCipherKey(), messageKeys.getIvSpec());
            return cipher.doFinal(gcmDecrypt(messageKeys.getCipherKey().toString().toCharArray(), cipherText));
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            throw new InvalidMessageException(e);
        }
    }

    /** todo: test: AES-GCM v2:
     * encrypt: AES-GCM
     * decrypt: AES-GCM
     * */

    public byte[] encrypt_v2(MessageKeys messageKeys, byte[] plaintext) {
        try {
            //todo: use AAD = messageKeys.getIv()
            Cipher cipher = Cipher.getInstance(GcmParams.AES_GCM);
            GCMParameterSpec parameterSpec = new GCMParameterSpec(128, messageKeys.getIv().getIV());
            cipher.init(Cipher.ENCRYPT_MODE, messageKeys.getCipherKey(), parameterSpec);
            return cipher.doFinal(plaintext);
        } catch (java.security.InvalidKeyException | InvalidAlgorithmParameterException | NoSuchPaddingException |
                NoSuchAlgorithmException | IllegalBlockSizeException | BadPaddingException e) {
            throw new AssertionError(e);
        }
    }

    //todo: Verify the GCM auth tag after decrypt !!!
    public byte[] decrypt_v2(MessageKeys messageKeys, byte[] cipherText) throws InvalidMessageException {
        try {
            Cipher cipher = Cipher.getInstance(GcmParams.AES_GCM);
            cipher.init(Cipher.DECRYPT_MODE, messageKeys.getCipherKey(), messageKeys.getIv());
            return cipher.doFinal(cipherText, 0, cipherText.length);
        } catch (NoSuchPaddingException | NoSuchAlgorithmException | java.security.InvalidKeyException |
                BadPaddingException | IllegalBlockSizeException | InvalidAlgorithmParameterException e) {
            throw new InvalidMessageException(e);
        }
    }

    /** todo: test: AES-GCM v3:
     * encrypt: AES_GCM(AES_GCM)
     * decrypt: AES_GCM(AES_GCM)
    * */

    public byte[] encrypt_v3(MessageKeys messageKeys, byte[] plaintext) throws Exception {
        try {
            //todo: use AAD = messageKeys.getIv() in gcmEncrypt and link to some GCM authentication tag
            //todo: use of the inner GCM authentication tag, as key material to the outer GCM
            Cipher cipher = Cipher.getInstance(GcmParams.AES_GCM);
            GCMParameterSpec parameterSpec = new GCMParameterSpec(128, messageKeys.getIv().getIV());
            cipher.init(Cipher.ENCRYPT_MODE, messageKeys.getCipherKey(), parameterSpec);
            return cipher.doFinal( gcmEncrypt(messageKeys.getCipherKey().toString().toCharArray(), plaintext) );
        } catch (java.security.InvalidKeyException | InvalidAlgorithmParameterException | NoSuchPaddingException |
                NoSuchAlgorithmException | IllegalBlockSizeException | BadPaddingException e) {
            throw new AssertionError(e);
        }
    }

    //todo: Verify the GCM auth tag after decrypt !!!
    public byte[] decrypt_v3(MessageKeys messageKeys, byte[] cipherText) throws Exception {
        try {
            Cipher cipher = Cipher.getInstance(GcmParams.AES_GCM);
            cipher.init(Cipher.DECRYPT_MODE, messageKeys.getCipherKey(), messageKeys.getIv());
            return gcmDecrypt( messageKeys.getCipherKey().toString().toCharArray(), cipher.doFinal(cipherText) );
        } catch (NoSuchPaddingException | NoSuchAlgorithmException | java.security.InvalidKeyException |
                BadPaddingException | IllegalBlockSizeException | InvalidAlgorithmParameterException e) {
            throw new InvalidMessageException(e);
        }
    }

    /** todo: test: AES-GCM variant 4:
     * encrypt:
     *  1. Inner encrypt: AES-GCM(message_keys.Key, message_keys.Iv) return cipher|gcm_auth_tag
     *  2. Outer encrypt: AES-GCM(Key=HKDF(gcm_auth_tag), Iv=generate(IV)) return IV|gcm_auth_tag|cipher
     * decrypt:
     *  1. Outer decrypt: AES-GCM(Key=HKDF(gcm_auth_tag), Iv=GetIv(IV|gcm_auth_tag|cipher), cipher=GetCipher(IV|gcm_auth_tag|cipher)) return cipher|gcm_auth_tag
     *  2. Inner decrypt: AES-GCM(message_keys.Key, message_keys.Iv, cipher=GetCipher(cipher|gcm_auth_tag)) return message
     * benefit:
     *  With private HKDF control decrypt out of the KeyChain for private implementation.
     * */

    public byte[] encrypt_v4(MessageKeys messageKeys, byte[] plaintext) {
        try {
            byte[] cip = gcmEncrypt(messageKeys.getCipherKey().toString().toCharArray(), plaintext);
            byte[] tag = Arrays.copyOfRange(cip, cip.length - GcmParams.GCM_TAG_LENGTH, cip.length);
            byte[] salt = new byte[GcmParams.SALT_LENGTH];
            secureRandom.nextBytes(salt);
            salt = java.util.Arrays.copyOfRange(hashes.getDigest(salt, hashes.SHA3L256), 0, GcmParams.SALT_LENGTH);
            SecretKey Key = generateKey(tag, salt);
            Cipher cipher = Cipher.getInstance(GcmParams.AES_GCM);
            GCMParameterSpec parameterSpec = new GCMParameterSpec(128, messageKeys.getIv().getIV()); //dtsonov: IV here is 16 not 12 bytes as javax.crypto says for the GCM IV !
            cipher.init(Cipher.ENCRYPT_MODE, Key, parameterSpec);
            byte[] cipherData = cipher.doFinal(cip);
            byte[] iv = messageKeys.getIv().getIV();
            ByteBuffer cypherBuffer = ByteBuffer.allocate(GcmParams.GCM_IV_LENGTH_16 + GcmParams.GCM_TAG_LENGTH + GcmParams.SALT_LENGTH + cipherData.length);
            cypherBuffer.put(iv);
            cypherBuffer.put(tag);
            cypherBuffer.put(salt);
            cypherBuffer.put(cipherData);
            return cypherBuffer.array(); // IV|gcm_auth_tag|salt|cipher;
        } catch (GeneralSecurityException e) {
            throw new AssertionError(e);
        }
    }

    //todo: Verify the GCM auth tag after decrypt !!!
    public byte[] decrypt_v4(MessageKeys messageKeys, byte[] cipherText) {
        try {
            SecretKey Key = generateKey(Arrays.copyOfRange(cipherText, GcmParams.GCM_IV_LENGTH_16, GcmParams.GCM_IV_LENGTH_16 + GcmParams.GCM_TAG_LENGTH),
                                        Arrays.copyOfRange(cipherText, GcmParams.GCM_IV_LENGTH_16 + GcmParams.GCM_TAG_LENGTH,
                                                GcmParams.GCM_IV_LENGTH_16 + GcmParams.GCM_TAG_LENGTH + GcmParams.SALT_LENGTH));
            Cipher cipher = Cipher.getInstance(GcmParams.AES_GCM);
            GCMParameterSpec parameterSpec = new GCMParameterSpec(128, Arrays.copyOfRange(cipherText, 0, GcmParams.GCM_IV_LENGTH_16));
            cipher.init(Cipher.DECRYPT_MODE, Key, parameterSpec);
            return gcmDecrypt(messageKeys.getCipherKey().toString().toCharArray(),
                                cipher.doFinal(Arrays.copyOfRange(cipherText,
                                        GcmParams.GCM_IV_LENGTH_16 + GcmParams.GCM_TAG_LENGTH + GcmParams.SALT_LENGTH, cipherText.length)));
        } catch (InvalidKeyException | InvalidAlgorithmParameterException | NoSuchPaddingException | NoSuchAlgorithmException |
                IllegalBlockSizeException | BadPaddingException | InvalidKeySpecException e) {
            throw new AssertionError(e);
        }
    }

    /**
     * Encrypt byte buffer.
    * */
    public byte[] encryptBuffer(Cipher GcmCipher, SecretKey Key, byte[] GcmIv, byte[] data, byte[] AAD) throws Exception {
        GCMParameterSpec parameterSpec = new GCMParameterSpec(128, GcmIv);
        GcmCipher.init(Cipher.ENCRYPT_MODE, Key, parameterSpec);
        if (AAD != null) { GcmCipher.updateAAD(AAD); }
        byte[] cipherData = GcmCipher.doFinal(data);
        ByteBuffer cipherBuffer = ByteBuffer.allocate(GcmParams.GCM_IV_LENGTH + GcmParams.AAD_LENGTH + cipherData.length);
        cipherBuffer.put(GcmIv); //GCM_IV_LENGTH=12 bytes
        cipherBuffer.put(AAD); // AAD=32 bytes
        cipherBuffer.put(cipherData); //data cipher
        return cipherBuffer.array(); //{IV|cipher}={16bytes|4MB}
    }

    /**
     * Decrypt byte buffer.
     * */
    public byte[] decryptBuffer(Cipher GcmCipher, SecretKey Key, byte[] cipher_data) throws Exception {
        AlgorithmParameterSpec gcmIv = new GCMParameterSpec(128, cipher_data, 0, GcmParams.GCM_IV_LENGTH);
        GcmCipher.init(Cipher.DECRYPT_MODE, Key, gcmIv);
        byte[] cip = org.bouncycastle.util.Arrays.copyOfRange(cipher_data, GcmParams.GCM_IV_LENGTH, cipher_data.length);
        //todo: Important: Verify GCM tag before return and remove it before write to file !!!
        return GcmCipher.doFinal(cip);
    }

    public byte[] getIV() throws GeneralSecurityException {
        byte[] iv = new byte[GcmParams.GCM_IV_LENGTH];
        secureRandom.nextBytes(iv);
        return Arrays.copyOfRange(hashes.getDigest(iv, hashes.BLAKE2s256), 0, GcmParams.GCM_IV_LENGTH);
    }

    public byte[] getAAD() throws GeneralSecurityException {
        byte[] aad = new byte[GcmParams.AAD_LENGTH];
        secureRandom.nextBytes(aad);
        return hashes.getDigest(aad, hashes.SHA3L256);
    }

    /* class private members */

    private SecretKey generateKey(char[] password, byte[] salt) throws NoSuchAlgorithmException, InvalidKeySpecException {  //dtsonov: todo: update with new HKDF
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance(GcmParams.ALGORITHM);
        KeySpec keySpec = new PBEKeySpec(password, salt, GcmParams.ITERATIONS, GcmParams.KEY_LENGTH);
        byte[] keyBytes = secretKeyFactory.generateSecret(keySpec).getEncoded();
        return new SecretKeySpec(keyBytes, GcmParams.AES);
    }

    private SecretKey generateKey(byte[] entropy, byte[] salt) throws InvalidKeySpecException, NoSuchAlgorithmException {    //dtsonov: control p2p encrypt/decrypt with this function
        SecretKey key = new SecretKeySpec(entropy, "AES");
        return generateKey(key.toString().toCharArray(), salt);
    }

    private byte[] gcmEncrypt(char[] password, byte[] plainText)
            throws GeneralSecurityException {

        byte[] salt = new byte[GcmParams.SALT_LENGTH];
        byte[] initVector = new byte[GcmParams.GCM_IV_LENGTH];

        secureRandom.nextBytes(salt);
        secureRandom.nextBytes(initVector);

        salt = java.util.Arrays.copyOfRange(hashes.getDigest(salt, hashes.BLAKE2s256), 0, GcmParams.SALT_LENGTH);
        initVector = java.util.Arrays.copyOfRange(hashes.getDigest(initVector, hashes.BLAKE2s256), 0, GcmParams.GCM_IV_LENGTH);

        SecretKey secretKey = generateKey(password, salt);
        Cipher cipher = Cipher.getInstance(GcmParams.AES_GCM);
        GCMParameterSpec parameterSpec = new GCMParameterSpec(128, initVector);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);

        //todo: May be use of AAD ?!? A note for GCM decryption too.

        byte[] cipherData = cipher.doFinal(plainText);

        ByteBuffer cypherBuffer = ByteBuffer.allocate(GcmParams.GCM_IV_LENGTH + GcmParams.SALT_LENGTH + cipherData.length);
        cypherBuffer.put(initVector); //GCM_IV_LENGTH=12bytes
        cypherBuffer.put(salt); //saltLength=8bytes
        cypherBuffer.put(cipherData); //msg cipher

        return cypherBuffer.array();
    }

    private byte[] gcmDecrypt(char[] password, byte[] encodedData)
            throws InvalidKeySpecException, NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {

        SecretKey secretKey = generateKey(password, Arrays.copyOfRange(encodedData, GcmParams.GCM_IV_LENGTH,
                GcmParams.GCM_IV_LENGTH + GcmParams.SALT_LENGTH));
        AlgorithmParameterSpec gcmIv = new GCMParameterSpec(128, encodedData, 0, GcmParams.GCM_IV_LENGTH);

        Cipher cipher = Cipher.getInstance(GcmParams.AES_GCM);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmIv);

        return cipher.doFinal(Arrays.copyOfRange(encodedData, GcmParams.GCM_IV_LENGTH + GcmParams.SALT_LENGTH, encodedData.length));
    }

    private Cipher getCipher(int mode, SecretKeySpec key, IvParameterSpec iv) {
        try {
            Cipher cipher = Cipher.getInstance(GcmParams.AES_CBC);
            cipher.init(mode, key, iv);
            return cipher;
        } catch (NoSuchAlgorithmException | NoSuchPaddingException |
                java.security.InvalidKeyException | InvalidAlgorithmParameterException e) {
            throw new AssertionError(e);
        }
    }
}