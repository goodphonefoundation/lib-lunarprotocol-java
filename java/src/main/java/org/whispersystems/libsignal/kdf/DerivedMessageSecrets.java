/**
 * Copyright (C) 2014-2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */

package org.whispersystems.libsignal.kdf;

import org.whispersystems.libsignal.util.ByteUtil;

import java.text.ParseException;

//import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class DerivedMessageSecrets {

  public  static final int SIZE              = 80;
  private static final int CIPHER_KEY_LENGTH = 32;
  private static final int MAC_KEY_LENGTH    = 32;
  //private static final int IV_LENGTH         = 16;
  private static final int GCM_IV_LENGTH         = 12;

  private final SecretKeySpec   cipherKey;
  private final SecretKeySpec   macKey;
  private final GCMParameterSpec iv; // dtsonov: Chang to GCM mode.

  public DerivedMessageSecrets(byte[] okm) {
    try {
      byte[][] keys = ByteUtil.split(okm, CIPHER_KEY_LENGTH, MAC_KEY_LENGTH, GCM_IV_LENGTH);

      this.cipherKey = new SecretKeySpec(keys[0], "AES");
      this.macKey    = new SecretKeySpec(keys[1], "HmacSHA256"); //dtsonov: Update HmacSHA algorithm. Need to test first.
      this.iv        = new GCMParameterSpec(128, keys[2]);
    } catch (ParseException e) {
      throw new AssertionError(e);
    }
  }

  public SecretKeySpec getCipherKey() {
    return cipherKey;
  }

  public SecretKeySpec getMacKey() { return macKey; }

  public GCMParameterSpec getIv() {
    return iv;
  }
}
