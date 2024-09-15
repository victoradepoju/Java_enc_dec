package rsa;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
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

public class RSAForClientSide {

    private PrivateKey privateKey;

    private static final String PRIVATE_KEY_STRING = "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDVP/d/PgFI+BL3g1dt6TJagx7yVpOsclD51+qHqcHKpFqmyv1QffZz1b5WUVS/cccD7TfA+l4MjRr5LtSIRx2J2KsNNVbdjoX4tZAR22oRtMXsQJOEY2QbLtGlBeNz6WdOW6KEKD2q9Ngjxz8jE0ZWqkoPAVVaQJQt7a12uq7OoQIE9UKBhBB/Tel7kTjWu9/efPQGgc+HGzV3p7Fo+uxCRkRUsqOTmGKaTrkX3IgWW2BQMlI3nAs2sKgRs6iFcGM/fmCHJJYzGN90GZcv9ja1/Tt+gGXsbEiuwUVO74m1zsqps7SutNr9Xy4lXywDGebsPo5c1zkg0HYWBRMVJZ7HAgMBAAECggEACPiQ69xq52vwOFNhKTGHOcGMWruDqNyCRZBswFpG2cSCP8QIVguGg6b5Q95WB1u8+JBRKSAfNr305Yivzi/XsUXZJEwbJGTrg+P3dJjbZHVLYj3xNr+LpY0ZqqyNvgGSo/w84PxkY727Hf4yzMHx0pGFXg47TfmrgicehgEie3S8yJbZqCd504QiC8KtMTMSqPcHvC+T7veM2LBr2efh5kiw9vewA+MdHcqZFwFWa6Xi0+cJYmBPDvhTZAJ/yZ2lgEOERZxwQYKIZBgYE8WLIG/usol+2b1wCy2AubwlNyBSgwT+8SiwM//Yt6rWyRpyJTyMZFYMXh2eGOcPNfu+mQKBgQDVVWJIUlcvfaWTf2a8U2EasLfR2z/ZEC6NDwMiUZ7eAwtjeMIL0XNAT+//h7DemSOZ+lhbd7lvgfK/RRyrzw1XcVTZHIGFNgkanLad4/Z7iHVQdAL9BDN+5V70g63jesuAW4Atd6wTM7hNamF5vLtE9adtxXd3qvohdJqHDqia/QKBgQD/5kyp3Vut7+0Wws7AH2sgLDhk0Yf2yQ5J3FCReZ/biG/3023ys9VfHnnxOEpbfh4yEPdHfqMOK3eVwYzihExJMMWpHGMx3SOmJCHd6tDBliwqUv3KqT1bsmXyJzHGnI2VlCqeIrvFN36DLZ1dObhOm/4jM7NCa4gglWxkvm/2EwKBgQCWT3LQQjPr4junkTxxtM3WYG0kD7cM2bny6YDrzVaCVuLPU2ZlrU3nImuXP6P/MydCdoGK8PBXANhoq+lnpJth4RhHYS5hDZGcjo6c8OHaaGtAJH12iF9AKZyd66m5feukpNPLNWaooOhao3nKrI/GJs+xKFDkoDNdHytBvbJOgQKBgQCBqXiY7V+Bz7srOEQ4VvMZ1y4v73dcFV3XEPoF7EGSpBxPz2K7gmGQE8on7qTGnS3BopUZNdJ64I10ZSD0uaJJx5uv54Ffh7SDf3Vlk5B5NpVkUK7l3EEJ0GgVfcSb5UFcVDoP7HuGH2tMHnXJAfEga6wmvBCNjBzqnavRlCj43wKBgBAzg2V5N3UVXUmFilQ+RN72MwvhplLe2jSdbuP5yC8I8wucIkGRR5gF/O9WIqCEihawYVSEXH1cCSSJtCdDgpRqFtdZVvQep/1C2v+ovc20k+DcgNqfoXDihb4JK/1tnXPjTMp8IbVqYttATb/zVEDZWu87CbNA/Gou7bDBPkFX";


    public void initFromStrings() throws NoSuchAlgorithmException, InvalidKeySpecException {
        PKCS8EncodedKeySpec keySpecPrivate = new PKCS8EncodedKeySpec(decode(PRIVATE_KEY_STRING));

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        privateKey = keyFactory.generatePrivate(keySpecPrivate);
    }

    public void printKeys() {
//        System.out.println("Public key\n" + encode(publicKey.getEncoded()));
        System.out.println("Private key\n" + encode(privateKey.getEncoded()));
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

        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }

    private byte[] decode(String data) {
        return Base64.getDecoder().decode(data);
    }
}
