/**
 * Copyright (C) 2014-2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */
package org.whispersystems.libsignal.ratchet;

import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/* dtsonov:
todo:
 Add source of AAD bytes from here, for the GCM mode.
 Replace all SecretKeySpec and GCM IV parameters with Hashed values using CryptoHashes class.
*/
public class MessageKeys {
  private final SecretKeySpec   cipherKey;
  private final SecretKeySpec   macKey;
  private final IvParameterSpec ivParamSpec;
  private final GCMParameterSpec iv;
  private final int             counter;
  private final int             AAD_LENGTH = 32;
  private byte[] AAD = new byte[AAD_LENGTH];

  /** Not in use with GCMParameterSpec*/
  public MessageKeys(SecretKeySpec cipherKey, SecretKeySpec macKey, GCMParameterSpec iv, byte[] Aad, int counter) {
    this.ivParamSpec = null;
    this.cipherKey = cipherKey;
    this.macKey    = macKey;
    this.iv        = iv;
    this.counter   = counter;
    this.AAD       = Aad;
  }

  /** Not in use with IvParameterSpec*/
  public MessageKeys(SecretKeySpec cipherKey, SecretKeySpec macKey, IvParameterSpec ivSpec, int counter) {
    this.iv        = null;
    this.cipherKey = cipherKey;
    this.macKey    = macKey;
    this.ivParamSpec = ivSpec;
    this.counter   = counter;
  }

  public SecretKeySpec getCipherKey() {
    return cipherKey;
  }

  public SecretKeySpec getMacKey() {
    return macKey;
  }

  public GCMParameterSpec getIv() {
    return iv;
  }

  public IvParameterSpec getIvSpec(){return ivParamSpec;}

  public int getCounter() {
    return counter;
  }

  public byte[] getAAD(){return AAD;};
}
