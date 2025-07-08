package io.github.mitsumi.solutions.ciphers;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Base64;
import java.util.Objects;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;


public class AESWithRSACipherTest {

    private final AESWithRSACipher aesWithRSACipher = AESWithRSACipher.build();

    @ParameterizedTest
    @CsvSource("/test-data/io.github.mitsumi.solutions.ciphers.AESWithRSACipherTest/public.key,/test-data/io.github.mitsumi.solutions.ciphers.AESWithRSACipherTest/private.key,test")
    public void test(String publicKeyPath, String privateKeyPath, String plainText) throws Exception {
        var publicKey = Files.readString(resourcePath(publicKeyPath));
        var privateKey = Files.readString(resourcePath(privateKeyPath));

        var actual = aesWithRSACipher.encrypt(publicKey, plainText.getBytes(StandardCharsets.UTF_8));

        assertThat(actual.encryptedKey(), is(notNullValue()));
        assertThat(actual.iv(), is(notNullValue()));
        assertThat(actual.encrypted(), is(notNullValue()));

        var actualDecrypted = aesWithRSACipher.decrypt(
            privateKey,
            Base64.getDecoder().decode(actual.encryptedKey()),
            Base64.getDecoder().decode(actual.iv()),
            Base64.getDecoder().decode(actual.encrypted())
        );

        assertThat(new String(actualDecrypted, StandardCharsets.UTF_8), is(plainText));
    }

    private Path resourcePath(String classPath) throws URISyntaxException {
        return Paths.get(Objects.requireNonNull(this.getClass().getResource(classPath)).toURI());
    }
}
