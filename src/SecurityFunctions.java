import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;

public class SecurityFunctions {

    // Generate Diffie-Hellman keys
    public static KeyPair generateDHKeyPair() throws Exception {
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("DH");
        keyPairGen.initialize(1024);
        return keyPairGen.generateKeyPair();
    }

    // AES Encryption
    public static byte[] encryptAES(String data, SecretKey key, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
        return cipher.doFinal(data.getBytes());
    }

    // RSA Encryption
    public static byte[] encryptRSA(String data, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(data.getBytes());
    }

    // HMAC SHA-384
    public static byte[] generateHMAC(String data, SecretKey key) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA384");
        mac.init(key);
        return mac.doFinal(data.getBytes());
    }

    // SHA-1 with RSA Signature
    public static byte[] signData(String data, PrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance("SHA1withRSA");
        signature.initSign(privateKey);
        signature.update(data.getBytes());
        return signature.sign();
    }
}
