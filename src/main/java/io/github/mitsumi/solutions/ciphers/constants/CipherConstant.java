package io.github.mitsumi.solutions.ciphers.constants;

import lombok.experimental.UtilityClass;

/**
 * represent cipher constant class.
 */
@UtilityClass
public final class CipherConstant {
    /**
     * ASE Transformation.
     */
    @SuppressWarnings("PMD.LongVariable")
    public final static String TRANSFORMATION_AES = "AES/CBC/PKCS5Padding";

    /**
     * AES Algorithm.
     */
    public final static String ALGORITHM_AES = "AES";

    /**
     * RSA Algorithm.
     */
    public final static String ALGORITHM_RSA = "RSA";
}
