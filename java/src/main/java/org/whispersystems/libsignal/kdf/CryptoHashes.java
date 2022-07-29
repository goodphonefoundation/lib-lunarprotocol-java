package org.whispersystems.libsignal.kdf;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;

/*
BLAKE2s, SHA3, RIPEMD160
* */
public class CryptoHashes extends BCProviderBase {

    public final String SHA3L256 = "SHA3-256";
    public final String SHA3L512 = "SHA3-512";
    public final String BLAKE2s256 = "Blake2s-256";
    public final String RipeMD160 = "RipeMD160";

    public byte[] getDigest(byte[] inputData, String algo) throws GeneralSecurityException {
        MessageDigest hash = MessageDigest.getInstance(algo, BouncyCastleProvider.PROVIDER_NAME);
        return hash.digest(inputData);
    }
}
