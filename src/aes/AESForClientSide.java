package aes;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

/**
 * Possible KEY_SIZE values are 128, 192 and 256
 * Possible T_LEN (Tag length) values are 128, 120, 112, 104 and 96
 */
public class AESForClientSide {

    private SecretKey key;
    private int T_LEN = 128;
    private byte[] IV;

    public void initFromStrings(String secretKey, String IV) {
        key = new SecretKeySpec(secretKey.getBytes(), "AES");
        this.IV = IV.getBytes();
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
        Cipher decryptionCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
//        GCMParameterSpec spec = new GCMParameterSpec(T_LEN, IV);

        IvParameterSpec spec = new IvParameterSpec(IV);
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
