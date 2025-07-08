# java-ciphers

![Java](https://img.shields.io/badge/java-%23ED8B00.svg?style=for-the-badge&logo=openjdk&logoColor=white) [![Licence](https://img.shields.io/github/license/Ileriayo/markdown-badges?style=for-the-badge)](./LICENSE)

# supported

- java version: 21

# dependency

- maven

  ```xml
  <dependency>
      <groupId>io.github.mitsumi-solutions-develop</groupId>
      <artifactId>java-ciphers</artifactId>
      <version>1.0.0</version>
  </dependency>
  ```

# provides

- AESEncrypter
- AESDecrypter
- RSAPublicKeyEncrypter
- RSAPrivateKeyDecrypter
- AESWithRSACipher

# usage for spring

```java
import io.github.mitsumi.solutions.ciphers.AESWithRSACipher;

@Bean
public AESWithRSACipher aesWithRSACipher() {
    return AESWithRSACipher.build();
}
```
