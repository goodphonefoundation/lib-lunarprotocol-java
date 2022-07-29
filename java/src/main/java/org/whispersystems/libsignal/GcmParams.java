package org.whispersystems.libsignal;

/**
 * Configuration parameters for different use cases of AES-GCM operation.
 * */
public class GcmParams {
    public final static String AES = "AES";
    public final static String AES_CBC = "AES/CBC/PKCS5Padding";
    public final static String AES_GCM = "AES/GCM/NoPadding";
    public final static String ALGORITHM = "PBKDF2WithHmacSHA1"; //dtsonov: todo: update with HKDF update
    public final static int SALT_LENGTH = 8;
    public final static int GCM_IV_LENGTH = 12; // GCMParameterSpec IV is 12bytes;
    public final static int GCM_IV_LENGTH_16 = 16;
    public final static int GCM_TAG_LENGTH = 16;
    public final static int AAD_LENGTH = 32;
    public final static int ITERATIONS = 1010;
    public final static int KEY_LENGTH = 256;
}
