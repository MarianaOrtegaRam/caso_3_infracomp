import java.io.*;
import java.math.BigInteger;
import java.net.*;
import java.security.*;
import java.util.HashMap;
import javax.crypto.*;
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
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

            // Paso 1: Recibir "SECINIT" y responder con "OK"
            String mensajeCliente = (String) in.readObject();
            System.out.println("Servidor: Recibió " + mensajeCliente);
            if ("SECINIT".equals(mensajeCliente)) {
                out.writeObject("OK");
                out.flush();
                System.out.println("Servidor: Envió OK");
            } else {
                System.out.println("Servidor: Mensaje inesperado recibido. Enviando ERROR y cerrando conexión.");
                out.writeObject("ERROR");
                out.flush();
                clientSocket.close();
                return;
            }

            // Paso 2: Recibir el desafío del cliente y responder con el mismo desafío
            byte[] clientChallenge = (byte[]) in.readObject();
            System.out.println("Servidor: Recibió desafío del cliente");
            out.writeObject(clientChallenge); // Responder con el mismo desafío
            out.flush();
            System.out.println("Servidor: Envió respuesta al desafío");

            // Paso 3: Esperar confirmación "OK" del cliente
            String challengeResponse = (String) in.readObject();
            if (!"OK".equals(challengeResponse)) {
                System.out.println("Error: Verificación del desafío fallida.");
                clientSocket.close();
                return;
            }
            System.out.println("Servidor: Desafío verificado exitosamente.");

            // Paso 7: Generar G, P y G^x (con un primo de 1024 bits)
            BigInteger G = new BigInteger("2"); // Generador comúnmente usado
            BigInteger P = new BigInteger("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
                                          + "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
                                          + "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
                                          + "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
                                          + "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
                                          + "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
                                          + "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
                                          + "670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF", 16);

            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH");
            DHParameterSpec dhParamSpec = new DHParameterSpec(P, G);
            keyGen.initialize(dhParamSpec);
            KeyPair dhKeyPair = keyGen.generateKeyPair();
            BigInteger Gx = ((DHPublicKey) dhKeyPair.getPublic()).getY();

            // Enviar G, P y G^x al cliente
            out.writeObject(G);
            out.writeObject(P);
            out.writeObject(Gx);
            out.flush();
            System.out.println("Servidor: Envió G, P y G^x");

            // Paso 11a: Recibir G^y del cliente y calcular la clave compartida
            BigInteger Gy = (BigInteger) in.readObject();
            BigInteger sharedSecret = Gy.modPow(((DHPrivateKey) dhKeyPair.getPrivate()).getX(), P);
            System.out.println("Servidor: Clave secreta compartida derivada: " + bytesToHex(sharedSecret.toByteArray()));

            // Derivar claves AES y HMAC a partir de la clave compartida
            byte[] secretBytes = sha512(sharedSecret.toByteArray());
            SecretKey aesKey = new SecretKeySpec(secretBytes, 0, 32, "AES");
            SecretKey macKey = new SecretKeySpec(secretBytes, 32, 32, "HmacSHA384");

            // Depuración: Imprimir claves derivadas
            System.out.println("Servidor: Clave AES derivada: " + bytesToHex(aesKey.getEncoded()));
            System.out.println("Servidor: Clave HMAC derivada: " + bytesToHex(macKey.getEncoded()));

            // Paso 12: Enviar IV al cliente
            IvParameterSpec iv = new IvParameterSpec(generateRandomIV());
            out.writeObject(iv.getIV());
            out.flush();
            System.out.println("Servidor: Envió IV: " + bytesToHex(iv.getIV()));

            // Continuar con los pasos siguientes del protocolo...

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

    // Método auxiliar para convertir bytes a formato hexadecimal
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    // Método auxiliar para generar el hash SHA-512 de un array de bytes
    private static byte[] sha512(byte[] input) throws NoSuchAlgorithmException {
        MessageDigest sha512 = MessageDigest.getInstance("SHA-512");
        return sha512.digest(input);
    }

    // Método auxiliar para generar un IV aleatorio de 16 bytes
    private static byte[] generateRandomIV() {
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        return iv;
    }
}
