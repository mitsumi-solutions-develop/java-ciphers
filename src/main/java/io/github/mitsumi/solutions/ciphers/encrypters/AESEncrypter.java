package io.github.mitsumi.solutions.ciphers.encrypters;

import io.github.mitsumi.solutions.ciphers.constants.CipherConstant;
import io.github.mitsumi.solutions.ciphers.generators.KeyGenerator;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;

/**
 * AES Encrypter class.
 */
@SuppressWarnings("PMD.ShortVariable")
public final class AESEncrypter {
    /**
     * AES Key length.
     */
    private final static int KEY_LENGTH = 32;

    /**
     * AES Iv length.
     */
    private final static int IV_LENGTH = 16;

    /**
     * Key generator.
     */
    private final KeyGenerator keyGenerator;

    /**
     * Build.
     *
     * @return AESEncrypter
     */
    public static AESEncrypter build() {
        return new AESEncrypter();
    }

    /**
     * Constructor.
     */
    private AESEncrypter() {
        this.keyGenerator = KeyGenerator.build();
    }

    /**
     * Encrypt specified plain text.
     *
     * @param plainText plain text
     * @return encrypted info
     */
    public AESEncryptedResult encrypt(final byte[] plainText) {
        try {
            final byte[] key = keyGenerator.generate(KEY_LENGTH);
            final byte[] iv = keyGenerator.generate(IV_LENGTH);

            final var cipher = Cipher.getInstance(CipherConstant.TRANSFORMATION_AES);
            cipher.init(
                Cipher.ENCRYPT_MODE,
                new SecretKeySpec(key, CipherConstant.ALGORITHM_AES),
                new IvParameterSpec(iv)
            );

            return new AESEncryptedResult(key, iv, cipher.doFinal(plainText));
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException(e);
        }
    }

    /**
     * AES Encrypted Result
     * @param key AES Key
     * @param iv AES Iv
     * @param encrypted encrypted text
     */
    public record AESEncryptedResult(
        byte[] key,
        byte[] iv,
        byte[] encrypted
    ) {}

}
