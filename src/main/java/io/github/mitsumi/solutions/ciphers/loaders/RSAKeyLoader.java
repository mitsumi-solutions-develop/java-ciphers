package io.github.mitsumi.solutions.ciphers.loaders;

import io.github.mitsumi.solutions.ciphers.constants.CipherConstant;
import lombok.NoArgsConstructor;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * RSA key loader class.
 */
@NoArgsConstructor(staticName = "build")
public class RSAKeyLoader {
    /**
     * Begin of public key string.
     */
    private final static String BEGIN_PUBLIC = "-----BEGIN PUBLIC KEY-----";

    /**
     * End of public key string.
     */
    private final static String END_PUBLIC = "-----END PUBLIC KEY-----";

    /**
     * Begin of private key string.
     */
    private final static String BEGIN_PRIVATE = "-----BEGIN PRIVATE KEY-----";

    /**
     * End of private key string.
     */
    private final static String END_PRIVATE = "-----END PRIVATE KEY-----";


    /**
     * Load {@code RSAPublicKey} by specified public key.
     *
     * @param publicKey public key
     * @return RSAPublicKey
     */
    public RSAPublicKey loadPublic(final String publicKey) {
        try {
            final var spec = new X509EncodedKeySpec(keyBytes(publicKey, BEGIN_PUBLIC, END_PUBLIC));
            final var factory = KeyFactory.getInstance(CipherConstant.ALGORITHM_RSA);

            return (RSAPublicKey) factory.generatePublic(spec);
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException("Failed to load key.", e);
        }
    }

    /**
     * Load {@code RSAPrivateKey} by specified private key.
     *
     * @param privateKey private key
     * @return RSAPrivateKey
     */
    public PrivateKey loadPrivate(final String privateKey) {
        try {
            final var spec = new PKCS8EncodedKeySpec(keyBytes(privateKey, BEGIN_PRIVATE, END_PRIVATE));
            final var factory = KeyFactory.getInstance(CipherConstant.ALGORITHM_RSA);

            return factory.generatePrivate(spec);
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException("Failed to load key.", e);
        }
    }

    private byte[] keyBytes(final String rsaKey,
                            final String replaceBegin,
                            final String replaceEnd) {
        final var key = rsaKey
            .replace(replaceBegin, "")
            .replace(replaceEnd, "")
            .replaceAll("\r", "")
            .replaceAll("\n", "");

        return Base64.getDecoder().decode(key);
    }
}
