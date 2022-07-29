package org.whispersystems.libsignal.kdf;

import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;
import org.bouncycastle.util.Strings;

/*
Hashed Password KDF class
Provides Argon2 as KDF.
* */
public class HPKDF extends BCProviderBase {

    public int DEFAULT_KEY_LEN = 32; // bytes

    public byte[] bytes2Key(int version, int iterations, int memory, int parallelism,
                            byte[] password, byte[] salt, int outputLength) {

        Argon2Parameters.Builder builder = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                .withVersion(version)
                .withIterations(iterations)
                .withMemoryPowOfTwo(memory)
                .withParallelism(parallelism)
                .withSalt(salt);

        Argon2BytesGenerator gen = new Argon2BytesGenerator();

        gen.init(builder.build());

        byte[] result = new byte[outputLength];

        gen.generateBytes(password, result, 0, result.length);

        return result;
    }


    public byte[] psswd2Key(int version, int iterations, int memory, int parallelism,
                            String password, String salt, int outputLength) {

        Argon2Parameters.Builder builder = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                .withVersion(version)
                .withIterations(iterations)
                .withMemoryPowOfTwo(memory)
                .withParallelism(parallelism)
                .withSalt(Strings.toByteArray(salt));

        Argon2BytesGenerator gen = new Argon2BytesGenerator();

        gen.init(builder.build());

        byte[] result = new byte[outputLength];

        gen.generateBytes(password.toCharArray(), result, 0, result.length);

        return result;

    }

}
