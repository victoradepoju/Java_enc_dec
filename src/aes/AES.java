package aes;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

/**
 * Possible KEY_SIZE values are 128, 192 and 256
 * Possible T_LEN (Tag length) values are 128, 120, 112, 104 and 96
 */
public class AES {

    private SecretKey key;
    private int KEY_SIZE = 128;
    private int T_LEN = 128;
    private byte[] IV;

    public void init() throws NoSuchAlgorithmException {
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(KEY_SIZE);
        key = generator.generateKey();
    }

    public String encrypt(String plainText) throws
            NoSuchPaddingException,
            NoSuchAlgorithmException,
            InvalidKeyException,
            IllegalBlockSizeException,
            BadPaddingException
    {
        byte[] plainTextByte = plainText.getBytes();
        Cipher encryptionCipher = Cipher.getInstance("AES/GCM/NoPadding");
        encryptionCipher.init(Cipher.ENCRYPT_MODE, key);
        IV = encryptionCipher.getIV();
        byte[] encryptedBytes = encryptionCipher.doFinal(plainTextByte);
        return encode(encryptedBytes);
    }

    public String decrypt(String encryptdMessage) throws
            NoSuchPaddingException,
            NoSuchAlgorithmException,
            InvalidAlgorithmParameterException,
            InvalidKeyException,
            IllegalBlockSizeException,
            BadPaddingException
    {
        byte[] encryptedBytes = decode(encryptdMessage);
        Cipher decryptionCipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(T_LEN, IV);
        decryptionCipher.init(Cipher.DECRYPT_MODE, key, spec);
        byte[] decryptedBytes = decryptionCipher.doFinal(encryptedBytes);
        return new String(decryptedBytes);
    }

    private String encode(byte[] data) {
        return Base64.getEncoder().encodeToString(data);
    }

    private byte[] decode(String data) {
        return Base64.getDecoder().decode(data);
    }

    public void exportKeys() {
        System.err.println("SecretKey: " + encode(key.getEncoded()));
        System.err.println("IV: " + encode(IV));
    }
}
