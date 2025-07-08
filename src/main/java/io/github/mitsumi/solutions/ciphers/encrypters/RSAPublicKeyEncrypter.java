package io.github.mitsumi.solutions.ciphers.encrypters;

import io.github.mitsumi.solutions.ciphers.constants.CipherConstant;
import io.github.mitsumi.solutions.ciphers.loaders.RSAKeyLoader;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;

/**
 * RSA Public key encrypter.
 */
public final class RSAPublicKeyEncrypter {

    /**
     * RSA key loader.
     */
    private final RSAKeyLoader rsaKeyLoader;

    /**
     * Build.
     *
     * @return RSAPublicKeyEncrypter.
     */
    public static RSAPublicKeyEncrypter build() {
        return new RSAPublicKeyEncrypter();
    }

    /**
     * Constructor.
     */
    private RSAPublicKeyEncrypter () {
        this.rsaKeyLoader = RSAKeyLoader.build();
    }

    /**
     * Encrypt plain text with a specified public key.
     *
     * @param publicKey public key
     * @param plainText plain text
     * @return encrypted text
     */
    public byte[] encrypt(final String publicKey, final byte[] plainText)  {
        return encrypt(rsaKeyLoader.loadPublic(publicKey), plainText);
    }

    /**
     * Encrypt plain text with a specified public key.
     *
     * @param publicKey public key
     * @param plainText plain text
     * @return encrypted text
     */
    public byte[] encrypt(final RSAPublicKey publicKey, final byte[] plainText)  {
        try {
            final var cipher = Cipher.getInstance(CipherConstant.ALGORITHM_RSA);
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);

            return cipher.doFinal(plainText);
        } catch (
            NoSuchAlgorithmException | NoSuchPaddingException |
            InvalidKeyException | IllegalBlockSizeException | BadPaddingException e
        ) {
            throw new IllegalArgumentException(e);
        }
    }
}
