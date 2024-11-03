// Importaciones necesarias...
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.Socket;
import java.security.*;
import java.util.Arrays;
import java.util.Map;
import javax.crypto.*;
import javax.crypto.spec.*;

public class ThreadServidor extends Thread {
   private Socket socket;
    private Map<String, Paquete> tablaPaquetes;
    private PrivateKey privateKey;
    private PublicKey publicKey;

    // Constructor de SrvThread con los cuatro parámetros necesarios
    public ThreadServidor(Socket socket, Map<String, Paquete> tablaPaquetes, PrivateKey privateKey, PublicKey publicKey) {
        this.socket = socket;
        this.tablaPaquetes = tablaPaquetes;
        this.privateKey = privateKey;
        this.publicKey = publicKey;
    }
    public void run() {
        try (ObjectInputStream in = new ObjectInputStream(socket.getInputStream());
             ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream())) {

            // Paso 0: Generar P y G usando OpenSSL
            BigInteger[] pg = DiffieHellmanParam.generatePG("C:\\path_to_openssl\\");
            BigInteger P = pg[0];
            BigInteger G = pg[1];

            // Paso 1: Recibir "SECINIT" del cliente
            String initMsg = in.readUTF();
            if (!"SECINIT".equals(initMsg)) {
                out.writeUTF("ERROR");
                return;
            }

            // Paso 2: Generar y enviar el reto cifrado
            SecureRandom random = new SecureRandom();
            int reto = random.nextInt();
            byte[] retoCifrado = cifrarRSA(reto, publicKey);
            out.writeObject(retoCifrado);

            // Paso 3: Recibir respuesta y verificar
            int respuesta = in.readInt();
            if (respuesta != reto) {
                out.writeUTF("ERROR");
                return;
            }
            out.writeUTF("OK");

            // Paso 4: Enviar P, G y G^x al cliente
            BigInteger x = new BigInteger(1024, random);
            BigInteger Gx = G.modPow(x, P); // G^x mod P
            out.writeObject(P);
            out.writeObject(G);
            out.writeObject(Gx);

            // Paso 5: Recibir G^y del cliente y calcular la clave compartida G^(xy)
            BigInteger Gy = (BigInteger) in.readObject();
            BigInteger sharedSecret = Gy.modPow(x, P);

            // Generar la clave simétrica y el HMAC usando SHA-512 y la clave compartida
            MessageDigest sha512 = MessageDigest.getInstance("SHA-512");
            byte[] sharedSecretBytes = sha512.digest(sharedSecret.toByteArray());
            SecretKey K_AB1 = new SecretKeySpec(Arrays.copyOfRange(sharedSecretBytes, 0, 32), "AES"); // Para cifrado
            SecretKey K_AB2 = new SecretKeySpec(Arrays.copyOfRange(sharedSecretBytes, 32, 64), "HmacSHA384"); // Para HMAC

            // Paso 6: Recibir y verificar datos del cliente (con HMAC)
            byte[] uidCifrado = (byte[]) in.readObject();
            byte[] uidHMAC = (byte[]) in.readObject();
            if (!verificarHMAC(uidCifrado, uidHMAC, K_AB2)) {
                out.writeUTF("ERROR");
                return;
            }

            // Descifrar UID
            String uid = descifrarAES(uidCifrado, K_AB1);

            // Paso 7: Responder al cliente
            out.writeUTF("OK");

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private byte[] cifrarRSA(int mensaje, PublicKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(BigInteger.valueOf(mensaje).toByteArray());
    }

    private boolean verificarHMAC(byte[] data, byte[] hmac, SecretKey key) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA384");
        mac.init(key);
        byte[] computedHmac = mac.doFinal(data);
        return Arrays.equals(computedHmac, hmac);
    }

    private String descifrarAES(byte[] data, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        byte[] iv = new byte[16];
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
        return new String(cipher.doFinal(data));
    }
}
