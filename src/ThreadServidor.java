import java.io.*;
import java.math.BigInteger;
import java.net.*;
import java.security.*;
import java.util.HashMap;
import javax.crypto.*;
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class ThreadServidor extends Thread {
    private final Socket clientSocket;
    private final HashMap<String, PackageInfo> packagesTable;
    private final KeyPair serverKeyPair;

    public ThreadServidor(Socket socket, HashMap<String, PackageInfo> packagesTable, KeyPair serverKeyPair) {
        this.clientSocket = socket;
        this.packagesTable = packagesTable;
        this.serverKeyPair = serverKeyPair;
    }

    public void run() {
        try (ObjectOutputStream out = new ObjectOutputStream(clientSocket.getOutputStream());
             ObjectInputStream in = new ObjectInputStream(clientSocket.getInputStream())) {

            // Step 1: Receive "SECINIT" and respond with "OK"
            String mensajeCliente = (String) in.readObject();
            System.out.println("Servidor: Recibió " + mensajeCliente);
            if ("SECINIT".equals(mensajeCliente)) {
                out.writeObject("OK");
                System.out.println("Servidor: Envió OK");

                // Step 2: Receive and respond to client's challenge
                byte[] clientChallenge = (byte[]) in.readObject();
                out.writeObject(clientChallenge); // Respond with the same challenge

                // Step 3: Wait for client's "OK" confirmation to proceed
                String challengeResponse = (String) in.readObject();
                if ("OK".equals(challengeResponse)) {
                    System.out.println("Servidor: Desafío verificado exitosamente.");

                    // Step 4: Diffie-Hellman Key Exchange
                    BigInteger G = (BigInteger) in.readObject();
                    BigInteger P = (BigInteger) in.readObject();
                    BigInteger Gx = (BigInteger) in.readObject();

                    // Generate server's DH key pair and calculate G^y
                    KeyPair dhKeyPair = generateDHKeyPair();
                    BigInteger Gy = ((DHPublicKey) dhKeyPair.getPublic()).getY();
                    BigInteger sharedSecret = Gx.modPow(((DHPrivateKey) dhKeyPair.getPrivate()).getX(), P);
                    System.out.println("Servidor: Clave secreta compartida derivada.");

                    // Step 5: Confirm Diffie-Hellman parameters and send G^y
                    out.writeObject("OK");
                    out.writeObject(Gy);

                    // Step 6: Derive AES and HMAC keys from the shared secret
                    byte[] secretBytes = sha512(sharedSecret.toByteArray());
                    SecretKey aesKey = new SecretKeySpec(secretBytes, 0, 32, "AES");
                    SecretKey macKey = new SecretKeySpec(secretBytes, 32, 32, "HmacSHA384");

                    // Step 7: Send Initialization Vector (IV) to client
                    IvParameterSpec iv = new IvParameterSpec(generateRandomIV());
                    out.writeObject(iv.getIV());

                    // Step 8: Receive and verify UID with HMAC
                    byte[] encryptedUid = (byte[]) in.readObject();
                    byte[] hmacUid = (byte[]) in.readObject();
                    String uid = new String(decryptAES(encryptedUid, aesKey, iv), "UTF-8");

                    if (MessageDigest.isEqual(hmacUid, generateHMAC(uid, macKey))) {
                        System.out.println("Servidor: HMAC del UID verificado exitosamente.");

                        // Step 9: Receive and verify package ID with HMAC
                        byte[] encryptedPackageId = (byte[]) in.readObject();
                        byte[] hmacPackageId = (byte[]) in.readObject();
                        String packageId = new String(decryptAES(encryptedPackageId, aesKey, iv), "UTF-8");

                        if (MessageDigest.isEqual(hmacPackageId, generateHMAC(packageId, macKey))) {
                            System.out.println("Servidor: HMAC del ID del paquete verificado exitosamente.");

                            // Step 10: Receive and verify request with HMAC
                            byte[] encryptedRequest = (byte[]) in.readObject();
                            byte[] hmacRequest = (byte[]) in.readObject();
                            String request = new String(decryptAES(encryptedRequest, aesKey, iv), "UTF-8");

                            if (MessageDigest.isEqual(hmacRequest, generateHMAC(request, macKey))) {
                                System.out.println("Servidor: HMAC de la solicitud verificado exitosamente.");

                                // Step 11: Send "TERMINAR" to confirm protocol completion
                                out.writeObject("TERMINAR");
                            } else {
                                System.out.println("Error: Verificación del HMAC de la solicitud fallida.");
                            }
                        } else {
                            System.out.println("Error: Verificación del HMAC del ID del paquete fallida.");
                        }
                    } else {
                        System.out.println("Error: Verificación del HMAC del UID fallida.");
                    }
                } else {
                    System.out.println("Error: Verificación del desafío fallida.");
                }
            } else {
                System.out.println("Error: No se recibió el mensaje SECINIT.");
            }
        } catch (Exception e) {
            System.out.println("Error al manejar el cliente: " + e.getMessage());
            e.printStackTrace();
        } finally {
            try {
                clientSocket.close();
            } catch (IOException e) {
                System.out.println("Error al cerrar el socket del cliente.");
            }
        }
    }

    // Utility methods for key generation, encryption, decryption, HMAC, etc.

    private static KeyPair generateDHKeyPair() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH");
        keyGen.initialize(1024);
        return keyGen.generateKeyPair();
    }

    private static byte[] generateRandomIV() {
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        return iv;
    }

    private static byte[] sha512(byte[] input) throws NoSuchAlgorithmException {
        MessageDigest sha512 = MessageDigest.getInstance("SHA-512");
        return sha512.digest(input);
    }

    private static byte[] decryptAES(byte[] encryptedData, SecretKey key, IvParameterSpec iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key, iv);
        return cipher.doFinal(encryptedData);
    }

    private static byte[] generateHMAC(String data, SecretKey key) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA384");
        mac.init(key);
        return mac.doFinal(data.getBytes());
    }
}
