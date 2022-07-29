/**
 * Copyright (C) 2013-2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */

package org.whispersystems.libsignal.kdf;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import java.security.Provider;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.crypto.params.Argon2Parameters;
import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.util.Strings;

import org.whispersystems.libsignal.logging.Log;

/*
The original HKDF implementation.
* */
public abstract class HKDF {
  private static final int HASH_OUTPUT_SIZE  = 32;

  public static HKDF createFor(int messageVersion) {
    switch (messageVersion) {
      case 2:  return new HKDFv2();
      case 3:  return new HKDFv3();
      default: throw new AssertionError("Unknown version: " + messageVersion);
    }
  }

  /* todo:
      1. Test the original implementation.
      2. Test with the latest changes.
  * */
  public byte[] deriveSecrets(byte[] inputKeyMaterial, byte[] info, int outputLength) {
    byte[] salt = new byte[HASH_OUTPUT_SIZE]; // dtsonov: empty salt !?!
    return deriveSecrets(inputKeyMaterial, salt, info, outputLength);
    //return deriveSecrets1(inputKeyMaterial, info, outputLength);
  }

  // dtsonov: Replacement of the original deriveSecrets(..) implementation.
  // inputKeyMaterial should be unique.
  public byte[] deriveSecrets1(byte[] inputKeyMaterial, byte[] info, int outputLength) {
    return expand1(inputKeyMaterial, info, outputLength);
  }

  // dtsonov: Test the original implementation with new changes.
  public byte[] deriveSecrets(byte[] inputKeyMaterial, byte[] salt, byte[] info, int outputLength) {
    /* byte[] prk = extract1(salt, inputKeyMaterial);
      return expand1(prk, info, outputLength);
    */
    byte[] prk = extract(salt, inputKeyMaterial);
    return expand(prk, info, outputLength);
  }

  /* dtsonov: obsolete */
  private byte[] extract(byte[] salt, byte[] inputKeyMaterial) {
    try {
      Mac mac = Mac.getInstance("HmacSHA256");
      mac.init(new SecretKeySpec(salt, "HmacSHA256"));
      return mac.doFinal(inputKeyMaterial);
    } catch (NoSuchAlgorithmException | InvalidKeyException e) {
      throw new AssertionError(e);
    }
  }

  private byte[] extract1(byte[] salt, byte[] inputKeyMaterial) { //dtsonov: replacement of extract(..)
    try {
      CryptoHashes hashes = new CryptoHashes();
      HPKDF keyGen = new HPKDF();
      return keyGen.bytes2Key(Argon2Parameters.ARGON2_VERSION_13, 1, 4, 1,  //dtsonov: Todo: Important: find best parameters for device !
              hashes.getDigest(inputKeyMaterial, hashes.SHA3L256), hashes.getDigest(salt, hashes.BLAKE2s256), keyGen.DEFAULT_KEY_LEN);
    } catch(GeneralSecurityException e){
      throw new AssertionError(e);
    }
  }

  /* dtsonov: obsolete */
  private byte[] expand(byte[] prk, byte[] info, int outputSize) {
    try {
      int                   iterations     = (int) Math.ceil((double) outputSize / (double) HASH_OUTPUT_SIZE);
      byte[]                mixin          = new byte[0];
      ByteArrayOutputStream results        = new ByteArrayOutputStream();
      int                   remainingBytes = outputSize;

      for (int i= getIterationStartOffset();i<iterations + getIterationStartOffset();i++) {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(prk, "HmacSHA256"));

        mac.update(mixin);
        if (info != null) {
          mac.update(info);
        }
        mac.update((byte)i);

        byte[] stepResult = mac.doFinal();
        int    stepSize   = Math.min(remainingBytes, stepResult.length);

        results.write(stepResult, 0, stepSize);

        mixin          = stepResult;
        remainingBytes -= stepSize;
      }

      return results.toByteArray();
    } catch (NoSuchAlgorithmException | InvalidKeyException e) {
      throw new AssertionError(e);
    }
  }

  private byte[] expand1(byte[] prk, byte[] info, int outputSize){ //dtsonov: replacement of expand(..)
    try {
      CryptoHashes hashes = new CryptoHashes();
      HPKDF keyGen = new HPKDF();
      return keyGen.bytes2Key(Argon2Parameters.ARGON2_VERSION_13, 1, 4, 1,  //dtsonov: Todo: Important: find best parameters for device !
              hashes.getDigest(prk, hashes.SHA3L256), hashes.getDigest(info, hashes.BLAKE2s256), outputSize);
    } catch(GeneralSecurityException e){
      throw new AssertionError(e);
    }
  }

  protected abstract int getIterationStartOffset();
}
