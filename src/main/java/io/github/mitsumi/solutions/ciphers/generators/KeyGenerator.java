package io.github.mitsumi.solutions.ciphers.generators;


import lombok.NoArgsConstructor;
import org.apache.commons.lang3.RandomStringUtils;

import java.nio.charset.StandardCharsets;

/**
 * Key generator class.
 */
@NoArgsConstructor(staticName = "build")
public class KeyGenerator {

    /**
     * Creates a random string of bytes whose length is the number of characters specified.
     *
     * @param count the length of string to create
     * @return the random string of bytes
     */
    @SuppressWarnings("PMD.CommentSize")
    public byte[] generate(final int count) {
        return RandomStringUtils.secure().nextAlphanumeric(count).getBytes(StandardCharsets.UTF_8);
    }

}
