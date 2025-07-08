package io.github.mitsumi.solutions.ciphers.decrypters;

import io.github.mitsumi.solutions.ciphers.constants.CipherConstant;
import lombok.NoArgsConstructor;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;

/**
 * AES Decrypter class.
 */
@NoArgsConstructor(staticName = "build")
public final class AESDecrypter {

    /**
     * Decrypt encrypted bytes by specified key, iv
     * @param key AES key
     * @param iv AES iv
     * @param encrypted encrypted bytes
     * @return plain text
     */
    @SuppressWarnings("PMD.ShortVariable")
    public byte[] decrypt(final byte[] key, final byte[] iv, final byte[] encrypted) {
        try {
            final var cipher = Cipher.getInstance(CipherConstant.TRANSFORMATION_AES);
            cipher.init(
                Cipher.DECRYPT_MODE,
                new SecretKeySpec(key, CipherConstant.ALGORITHM_AES),
                new IvParameterSpec(iv)
            );

            return cipher.doFinal(encrypted);
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException(e);
        }
    }
}
