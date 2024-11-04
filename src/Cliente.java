import java.io.*;
import java.math.BigInteger;
import java.net.*;
import java.security.*;
import javax.crypto.*;
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Cliente {
    private static final String SERVER_ADDRESS = "localhost";
    private static final int SERVER_PORT = 12345;

    private static PublicKey serverPublicKey;
    private static SecretKey symmetricKey;
    private static SecretKey macKey;
    private static IvParameterSpec iv;

    public static void main(String[] args) {
        try (Socket socket = new Socket(SERVER_ADDRESS, SERVER_PORT);
             ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
             ObjectInputStream in = new ObjectInputStream(socket.getInputStream())) {

            // Step 1: Send "SECINIT" to initiate the protocol
            out.writeObject("SECINIT");

            // Step 2b: Generate a challenge (R) and send it to the server
            byte[] challenge = generateRandomChallenge();
            out.writeObject(challenge);

            // Step 4: Receive Rta (server’s response to the challenge)
            byte[] response = (byte[]) in.readObject();

            // Step 5: Verify Rta == R (in this example, we simply check if they match)
            if (!MessageDigest.isEqual(response, challenge)) {
                System.out.println("Challenge response verification failed.");
                return;
            }
            out.writeObject("OK");

            // Step 7: Diffie-Hellman Key Exchange - Send G, P, G^x to the server
            KeyPair dhKeyPair = generateDHKeyPair();
            BigInteger G = getGenerator();
            BigInteger P = getPrime();
            BigInteger Gx = ((DHPublicKey) dhKeyPair.getPublic()).getY();

            out.writeObject(G);
            out.writeObject(P);
            out.writeObject(Gx);

            // Step 9: Receive "OK" or "ERROR" based on server verification
            String verificationStatus = (String) in.readObject();
            if (!"OK".equals(verificationStatus)) {
                System.out.println("Server verification failed.");
                return;
            }

            // Step 11a: Receive Gy from server, calculate symmetric keys
            BigInteger Gy = (BigInteger) in.readObject();
            BigInteger sharedSecret = Gy.modPow(((DHPrivateKey) dhKeyPair.getPrivate()).getX(), P);

            // Step 11b: Derive AES and HMAC keys from the shared secret
            byte[] secretBytes = sha512(sharedSecret.toByteArray());
            symmetricKey = new SecretKeySpec(secretBytes, 0, 32, "AES");
            macKey = new SecretKeySpec(secretBytes, 32, 32, "HmacSHA384");

            // Step 12: Receive IV from server
            iv = new IvParameterSpec((byte[]) in.readObject());

            // Step 13: Send UID and HMAC to the server
            String uid = "client0";
            byte[] encryptedUid = encryptAES(uid, symmetricKey, iv);
            byte[] hmacUid = generateHMAC(uid, macKey);

            out.writeObject(encryptedUid);
            out.writeObject(hmacUid);

            // Step 14: Send package ID and HMAC to the server
            String packageId = "package0";
            byte[] encryptedPackageId = encryptAES(packageId, symmetricKey, iv);
            byte[] hmacPackageId = generateHMAC(packageId, macKey);

            out.writeObject(encryptedPackageId);
            out.writeObject(hmacPackageId);

            // Step 16: Send request for package status and HMAC
            String request = "estado";
            byte[] encryptedRequest = encryptAES(request, symmetricKey, iv);
            byte[] hmacRequest = generateHMAC(request, macKey);

            out.writeObject(encryptedRequest);
            out.writeObject(hmacRequest);

            // Step 17: Receive response from server
            String responseStatus = (String) in.readObject();
            if ("TERMINAR".equals(responseStatus)) {
                System.out.println("Protocol completed successfully.");
            } else {
                System.out.println("Error in protocol execution.");
            }

        } catch (Exception e) {
            System.out.println("Client error: " + e.getMessage());
            e.printStackTrace();
        }
    }

    // Utility methods

    private static byte[] generateRandomChallenge() {
        byte[] challenge = new byte[16];
        new SecureRandom().nextBytes(challenge);
        return challenge;
    }

    private static KeyPair generateDHKeyPair() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH");
        keyGen.initialize(1024);
        return keyGen.generateKeyPair();
    }

    private static BigInteger getGenerator() {
        // Generate generator G (in real cases, retrieve from a trusted source)
        return BigInteger.valueOf(2);
    }

    private static BigInteger getPrime() {
        // Generate a large prime P (in real cases, retrieve from a trusted source)
        return new BigInteger("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1", 16);
    }

    private static byte[] sha512(byte[] input) throws NoSuchAlgorithmException {
        MessageDigest sha512 = MessageDigest.getInstance("SHA-512");
        return sha512.digest(input);
    }

    private static byte[] encryptAES(String data, SecretKey key, IvParameterSpec iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        return cipher.doFinal(data.getBytes());
    }

    private static byte[] generateHMAC(String data, SecretKey key) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA384");
        mac.init(key);
        return mac.doFinal(data.getBytes());
    }
}
