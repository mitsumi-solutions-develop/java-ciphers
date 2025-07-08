package io.github.mitsumi.solutions.ciphers.decrypters;

import io.github.mitsumi.solutions.ciphers.constants.CipherConstant;
import io.github.mitsumi.solutions.ciphers.loaders.RSAKeyLoader;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;

/**
 * RSA Private key decrypter class.
 */
public final class RSAPrivateKeyDecrypter {
    /**
     * RSA Key loader.
     */
    private final RSAKeyLoader rsaKeyLoader;

    /**
     * Build.
     *
     * @return RSAPrivateKeyDecrypter
     */
    public static RSAPrivateKeyDecrypter build() {
        return new RSAPrivateKeyDecrypter();
    }

    /**
     * Constructor.
     */
    private RSAPrivateKeyDecrypter () {
        this.rsaKeyLoader = RSAKeyLoader.build();
    }

    /**
     * Decrypt encrypted bytes with a specified private key.
     *
     * @param privateKey private key
     * @param encrypted encrypted bytes
     * @return plain text
     */
    public byte[] decrypt(final String privateKey, final byte[] encrypted) {
        return decrypt(rsaKeyLoader.loadPrivate(privateKey), encrypted);
    }

    /**
     * Decrypt encrypted bytes with a specified private key.
     *
     * @param privateKey private key
     * @param encrypted encrypted bytes
     * @return plain text
     */
    public byte[] decrypt(final PrivateKey privateKey, final byte[] encrypted) {
        try {
            final var cipher = Cipher.getInstance(CipherConstant.ALGORITHM_RSA);
            cipher.init(Cipher.DECRYPT_MODE, privateKey);

            return cipher.doFinal(encrypted);
        } catch (
            NoSuchAlgorithmException | NoSuchPaddingException |
            InvalidKeyException | IllegalBlockSizeException | BadPaddingException e
        ) {
            throw new IllegalArgumentException(e);
        }
    }
}
