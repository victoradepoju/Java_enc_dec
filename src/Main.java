import aes.AES;
import aes.AESForClientSide;
import aes.AESWithSeparatedKey;
import rsa.RSAForClientSide;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

public class Main {
    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, UnsupportedEncodingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
//        RSA rsa = new RSA();
//        String encryptedHelloWorld = rsa.
//                encrypt("Hello World");
//        String decryptedHelloWorld = rsa
//                .decrypt(encryptedHelloWorld);
//
//        System.out.println("Encrypted:\n" + encryptedHelloWorld);
//        System.out.println("Decrypted:\n" + decryptedHelloWorld);


//        rsa.RSAWithSeparatedKeys rsaWithSeparatedKeys = new rsa.RSAWithSeparatedKeys();
//        rsaWithSeparatedKeys.initFromStrings();
//        String newEncryptedHelloWorld = rsaWithSeparatedKeys.
//                encrypt("Hello World");
//        String newDecryptedHelloWorld = rsaWithSeparatedKeys
//                .decrypt(newEncryptedHelloWorld);
//
//        System.out.println("Encrypted:\n" + newEncryptedHelloWorld);
//        System.out.println("Decrypted:\n" + newDecryptedHelloWorld);
//
//        rsaWithSeparatedKeys.printKeys();

//        RSAForClientSide rsaForClientSide = new RSAForClientSide();
//        rsaForClientSide.initFromStrings();
//        String fromServer = rsaForClientSide.decrypt("OAtSCSgKwHRE5YJdS+2ZR/h/5mSdRZ0xTzPgqgKufhPwAEvg2mvyRTytzDrldEcxXRBqnbYBi/KihWsSHmiA4vYqIR6XGDUPPOu6lu1BXBKC9AM7NaDRZ7VMgV68ed4fctDmTiGVYcCS/suYeeIcNTSxkamVvqsi22QczPj0BHRtdHkhFxomKstUn17uI8S21PECxvIdzP3xjfg4PXOxlzDA4X6DYKdg0s70e9Yk2028CMxDsCK0ksmFWXnPa5awTKe1EAQ1Rm4XoiZ66Cddqbgo90/nt9PPfewM1EWdyghXEtkAPSBqGxSMbK5tQ20Lv4/Gv7liUGglKBzthDHj3g==");
//        System.out.println("Password:\n" + fromServer);

//        String wordToEncrypt = "Helloooooo woooooorrrrrld";
//        AESWithSeparatedKey aes = new AESWithSeparatedKey();
//        aes.initFromStrings("n/xKrMVMXg86HL9V946fmw==", "GEDsX8pPNsmz+7v9");
//        String encryptedMessage = aes.encrypt(wordToEncrypt);
//        String decryptedMessage = aes.decrypt(encryptedMessage);
//        System.out.println("Encrypted:\n" + encryptedMessage);
//        System.out.println("Decrypted:\n" + decryptedMessage);
//        aes.exportKeys();


        AESForClientSide aesForClientSide = new AESForClientSide();
        aesForClientSide.initFromStrings("WAMqCYKhplpGHKwsFQOLrldeJwyXVmBL", "0123456789ABCDEF");
        String fromServer = aesForClientSide.decrypt("MqayKk+qPGXiSvmrRKIzgpIY9jPWckvRvHNsRpgloCw=");
        System.out.println("From server:\n" + fromServer);
    }
}