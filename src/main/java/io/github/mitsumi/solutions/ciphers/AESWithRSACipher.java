package io.github.mitsumi.solutions.ciphers;


import io.github.mitsumi.solutions.ciphers.decrypters.AESDecrypter;
import io.github.mitsumi.solutions.ciphers.decrypters.RSAPrivateKeyDecrypter;
import io.github.mitsumi.solutions.ciphers.encrypters.AESEncrypter;
import io.github.mitsumi.solutions.ciphers.encrypters.RSAPublicKeyEncrypter;

import java.util.Base64;

/**
 * AES with RSA cipher class.
 */
@SuppressWarnings({"PMD.LongVariable", "PMD.CommentSize", "PMD.ShortVariable"})
public final class AESWithRSACipher {

    /**
     * AES Encrypter.
     */
    private final AESEncrypter aesEncrypter;

    /**
     * AES Decrypter.
     */
    private final AESDecrypter aesDecrypter;

    /**
     * RSA PublicKey Encrypter.
     */
    private final RSAPublicKeyEncrypter publicKeyEncrypter;

    /**
     * RSA PrivateKey Decrypter.
     */
    private final RSAPrivateKeyDecrypter privateKeyDecrypter;

    /**
     * Build.
     *
     * @return AESWithRSACipher
     */
    public static AESWithRSACipher build() {
        return new AESWithRSACipher();
    }

    /**
     * Constructor.
     */
    private AESWithRSACipher() {
        this.aesEncrypter = AESEncrypter.build();
        this.aesDecrypter = AESDecrypter.build();
        this.publicKeyEncrypter = RSAPublicKeyEncrypter.build();
        this.privateKeyDecrypter = RSAPrivateKeyDecrypter.build();
    }

    /**
     * Encrypt plain text with AES and RSA public key.
     *
     * <ul>
     *     <li>Encrypt plain text with AES.</li>
     *     <li>Encrypt AES Key with RSA Public key</li>
     * </ul>
     *
     * AESWithRSAEncryptedResult
     * <ul>
     *     <li>
     *         Base64 encoded string(aes key : encrypted with rsa public key)
     *     </li>
     *     <li>
     *         Base64 encoded string(aes iv)
     *     </li>
     *     <li>
     *         Base64 encoded string(encrypted with aes)
     *     </li>
     * </ul>
     *
     * @param publicKey public key
     * @param plainText plain text
     * @return AESWithRSAEncrypted
     */
    public AESWithRSAEncryptedResult encrypt(final String publicKey, final byte[] plainText) {
        final var aesEncrypted = aesEncrypter.encrypt(plainText);
        final var encryptedKey = publicKeyEncrypter.encrypt(publicKey, aesEncrypted.key());

        return new AESWithRSAEncryptedResult(
            Base64.getEncoder().encodeToString(encryptedKey),
            Base64.getEncoder().encodeToString(aesEncrypted.iv()),
            Base64.getEncoder().encodeToString(aesEncrypted.encrypted())
        );
    }

    /**
     * Decrypt with private key and aes.
     *
     * <ul>
     *     <li>
     *         Decrypt encrypted key with rsa private key.
     *     </li>
     *     <li>
     *         Decrypt encrypted text with aes
     *     </li>
     * </ul>
     *
     * @param privateKey private key
     * @param encryptedKey encrypted aes key
     * @param iv aes iv
     * @param encrypted encrypted text
     * @return decrypted text
     */
    public byte[] decrypt(final String privateKey, final byte[] encryptedKey, final byte[] iv, final byte[] encrypted) {
        final var rsaDecryptedKey = privateKeyDecrypter.decrypt(privateKey, encryptedKey);
        return aesDecrypter.decrypt(rsaDecryptedKey, iv, encrypted);
    }

    /**
     * Encrypted result.
     *
     * @param encryptedKey encrypted aes key(base64 encoded string)
     * @param iv aes iv(base64 encoded string)
     * @param encrypted encrypted text(base64 encoded string)
     */
    public record AESWithRSAEncryptedResult(
        String encryptedKey,
        String iv,
        String encrypted
    ) {}
}
