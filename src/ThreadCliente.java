import java.io.*;
import java.math.BigInteger;
import java.net.*;
import java.security.*;
import javax.crypto.*;
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class ThreadCliente extends Thread {
    private static final String SERVER_ADDRESS = "localhost";
    private static final int SERVER_PORT = 12345;

    private static SecretKey K_AB1;
    private static SecretKey K_AB2;
    private static IvParameterSpec iv;

    private boolean isIterative;

    public ThreadCliente(boolean isIterative) {
        this.isIterative = isIterative;
    }

    public void run() {
        if (this.isIterative) {
            for (int i = 0; i < 32; i++) {
                System.out.println("Iteración " + i);
                theExecution();
            }
        } else {
            theExecution();
        }
    }

    public void theExecution() {
        try (Socket socket = new Socket(SERVER_ADDRESS, SERVER_PORT);
                ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
                ObjectInputStream in = new ObjectInputStream(socket.getInputStream())) {

            // Paso 1: Enviar "SECINIT" para iniciar el protocolo
            out.writeObject("SECINIT"); // Cliente envía "SECINIT"
            out.flush();
            System.out.println("Cliente: Envió SECINIT");

            // Paso 2: Recibir confirmación "OK" del servidor
            String respuestaServidor = (String) in.readObject();
            System.out.println("Cliente: Recibió " + respuestaServidor);
            if (!"OK".equals(respuestaServidor)) {
                throw new IOException("Desajuste en el protocolo: Se esperaba OK, se recibió " + respuestaServidor);
            }

            // Paso 2b: Generar un desafío (R) y enviarlo al servidor
            byte[] challenge = generateRandomChallenge();
            out.writeObject(challenge);

            // Paso 4: Recibir Rta (respuesta del servidor al desafío)
            byte[] response = (byte[]) in.readObject();
            if (!MessageDigest.isEqual(response, challenge)) {
                System.out.println("Error: El servidor no pasó la verificación del desafío.");
                return;
            }
            out.writeObject("OK");

            // Paso 7: Recibir G, P y G^x del servidor
            BigInteger G = (BigInteger) in.readObject();
            BigInteger P = (BigInteger) in.readObject();
            BigInteger Gx = (BigInteger) in.readObject();
            System.out.println("Cliente: Recibió G, P y G^x");

            // Generar clave Diffie-Hellman usando los parámetros G y P recibidos
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH");
            DHParameterSpec dhParamSpec = new DHParameterSpec(P, G);
            keyGen.initialize(dhParamSpec);
            KeyPair dhKeyPair = keyGen.generateKeyPair();
            BigInteger Gy = ((DHPublicKey) dhKeyPair.getPublic()).getY();

            // Paso 11a: Enviar G^y al servidor
            out.writeObject(Gy);
            out.flush();
            System.out.println("Cliente: Envió G^y");

            // Calcular la clave compartida
            BigInteger sharedSecret = Gx.modPow(((DHPrivateKey) dhKeyPair.getPrivate()).getX(), P);
            System.out.println(
                    "Cliente: Clave secreta compartida derivada: " + bytesToHex(sharedSecret.toByteArray()));

            // Derivar claves AES y HMAC a partir de la clave compartida
            byte[] secretBytes = sha512(sharedSecret.toByteArray());
            K_AB1 = new SecretKeySpec(secretBytes, 0, 32, "AES");
            K_AB2 = new SecretKeySpec(secretBytes, 32, 32, "HmacSHA384");

            // Depuración: Imprimir claves derivadas
            System.out.println("Cliente: Clave AES derivada: " + bytesToHex(K_AB1.getEncoded()));
            System.out.println("Cliente: Clave HMAC derivada: " + bytesToHex(K_AB2.getEncoded()));

            // Paso 12: Recibir IV del servidor
            iv = new IvParameterSpec((byte[]) in.readObject());
            System.out.println("Cliente: Recibió IV: " + bytesToHex(iv.getIV()));

            // Continuar con los pasos siguientes según el protocolo...

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

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

}
