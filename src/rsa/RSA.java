package rsa;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Base64;

/**
 * @author Victor Adepoju
 * <ul>
 *     <li>AES/CBC/NoPadding (128)</li>
 *     <li>AES/CBC/PKCS5Padding (128)</li>
 *     <li>AES/ECB/NoPadding (128)</li>
 *     <li>AES/ECB/PKCS5Padding (128)</li>
 *     <li>rsa.RSA/ECB/PKCS1Padding (1024, 2048)</li>
 *     <li>rsa.RSA/ECB/OAEPWithSHA-1AndMGF1Padding (1024, 2048)</li>
 *     <li>rsa.RSA/ECB/OAEPWithSHA-256AndMGF1Padding (1024, 2048)</li>
 * </ul>
 * <p>
 * for more details @see <a href="https://docs.oracle.com/javase/7/docs/api/javax/crypto/Cipher.html">Java Ciphers</a>
 */

public class RSA {

    private PrivateKey privateKey;
    private PublicKey publicKey;

    public RSA() throws NoSuchAlgorithmException
    {
        KeyPairGenerator generator = KeyPairGenerator
                .getInstance("RSA");
        KeyPair keyPair = generator.generateKeyPair();

        privateKey = keyPair.getPrivate();
        publicKey = keyPair.getPublic();

        generator.initialize(1024);
    }

    public String encrypt(String plainText) throws
            NoSuchPaddingException,
            NoSuchAlgorithmException,
            InvalidKeyException,
            IllegalBlockSizeException,
            BadPaddingException
    {
        byte[] plainTextToByte = plainText.getBytes(); // why no StandardCharset?
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        byte[] encryptedBytes = cipher.doFinal(plainTextToByte);

        return encode(encryptedBytes);
    }

    /**
     * The encryption has already been done.
     * This method only encodes to String.
     * @param data
     * @return String
     */
    private String encode(byte[] data) {
        return Base64.getEncoder().encodeToString(data);
    }

    public String decrypt(String encryptedText) throws
            UnsupportedEncodingException,
            IllegalBlockSizeException,
            BadPaddingException,
            InvalidKeyException,
            NoSuchPaddingException,
            NoSuchAlgorithmException
    {
        byte[] encryptedBytes = decode(encryptedText);

        Cipher cipher = Cipher.getInstance("rsa.RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }

    private byte[] decode(String data) {
        return Base64.getDecoder().decode(data);
    }
}
