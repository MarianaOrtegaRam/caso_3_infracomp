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
    private final PublicKey publicKey;
    private String userId;
    private String packageId;

    public ThreadCliente(boolean isIterative, int id) throws Exception {
        this.isIterative = isIterative;
        this.userId = "client" + id;
        this.publicKey = loadPublicKey("publicKey.ser");
        this.packageId = "package" + id;
    }

    public void run() {
        if (this.isIterative) {
            for (int i = 0; i < 64; i++) {
                System.out.println("Iteración " + i);
                this.packageId = "package" + i;
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

            // Paso 2a: Generar desafío R y cifrarlo con la llave pública del servidor

            // CASO 4: PARTE ASIMETRICA
            long startTimeA = System.nanoTime();
            byte[] R = generateRandomChallenge();
            byte[] encryptedR = encryptWithPublicKey(R, publicKey);
            out.writeObject(encryptedR);
            out.flush();
            System.out.println("Cliente: Enviado desafío cifrado al servidor");
            long endTimeA = System.nanoTime();
            long durationA = endTimeA - startTimeA;
            double milisegundosA = (double) durationA / 1000000.0;

            // Paso 4: Recibir RTA (respuesta del servidor)
            byte[] RTA = (byte[]) in.readObject();

            // Paso 5: Verificar si RTA es igual a R
            if (MessageDigest.isEqual(R, RTA)) {
                System.out.println("Cliente: Verificación exitosa, el servidor respondió correctamente.");
                out.writeObject("OK");
            } else {
                System.out.println("Cliente: Error en la verificación, cerrando conexión.");
                out.writeObject("ERROR");
                socket.close();
                return;
            }

            // Paso 8: Recibir G, P y G^x del servidor
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

            //11a Derivar claves AES(K_AB1) y HMAC (K_AB2) a partir de la clave compartida
            byte[] secretBytes = sha512(sharedSecret.toByteArray());
            K_AB1 = new SecretKeySpec(secretBytes, 0, 32, "AES");
            K_AB2 = new SecretKeySpec(secretBytes, 32, 32, "HmacSHA384");

            // Depuración: Imprimir claves derivadas
            System.out.println("Cliente: Clave AES derivada: " + bytesToHex(K_AB1.getEncoded()));
            System.out.println("Cliente: Clave HMAC derivada: " + bytesToHex(K_AB2.getEncoded()));

            // Paso 12: Recibir IV del servidor
            iv = new IvParameterSpec((byte[]) in.readObject());
            System.out.println("Cliente: Recibió IV: " + bytesToHex(iv.getIV()));

            // Paso 13: Enviar ID de usuario cifrado y HMAC
            byte[] encryptedUserId = encryptAES(userId, K_AB1, iv);
            byte[] hmacUserId = generateHMAC(userId, K_AB2);

            out.writeObject(encryptedUserId);
            out.writeObject(hmacUserId);

            // Paso 14: Enviar ID de paquete cifrado y HMAC
            byte[] encryptedPackageId = encryptAES(packageId, K_AB1, iv);
            byte[] hmacPackageId = generateHMAC(packageId, K_AB2);

            out.writeObject(encryptedPackageId);
            out.writeObject(hmacPackageId);

            // Paso 16: Recibir estado del paquete cifrado y su HMAC
            byte[] encryptedPackageStatus = (byte[]) in.readObject();
            byte[] hmacPackageStatus = (byte[]) in.readObject();
            String decryptedPackageStatus = new String(decryptAES(encryptedPackageStatus, K_AB1, iv), "UTF-8");

            // Paso 17: Verificar HMAC del estado del paquete
            byte[] calculatedHmacStatus = generateHMAC(decryptedPackageStatus, K_AB2);
            if (MessageDigest.isEqual(hmacPackageStatus, calculatedHmacStatus)) {
                System.out.println("Cliente: El estado del paquete es auténtico.");
                System.out.println(decryptedPackageStatus);
            } else {
                System.out.println("Cliente: Error de autenticidad en el estado del paquete.");
                return;
            }

            // Paso 18: Enviar "TERMINAR" y cerrar conexión
            out.writeObject("TERMINAR");
            out.flush();
            System.out.println("Cliente: Protocolo completado, cerrando conexión.");
            System.out.println("Tiempo de ejecución asimétrico: " + milisegundosA + " milisegundos");
        } catch (EOFException e) {
            System.out.println("Client error: Conexión finalizada inesperadamente.");

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

    private byte[] encryptWithPublicKey(byte[] data, PublicKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(data);
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

    private byte[] decryptAES(byte[] encryptedData, SecretKey key, IvParameterSpec iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key, iv);
        return cipher.doFinal(encryptedData);
    }

    private PublicKey loadPublicKey(String filePath) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(filePath))) {
            return (PublicKey) ois.readObject();
        }
    }

}
