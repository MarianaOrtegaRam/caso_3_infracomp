import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.Socket;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Random;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class ClienteRunnable implements Runnable {
    private final int clienteId;

    public ClienteRunnable(int clienteId) {
        this.clienteId = clienteId;
    }

    public void run() {
        try (Socket socket = new Socket("localhost", 12345);
             ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
             ObjectInputStream in = new ObjectInputStream(socket.getInputStream())) {

            // Paso 1: Iniciar protocolo con "SECINIT"
            out.writeUTF("SECINIT");

            // Paso 2: Recibir y descifrar el reto
            byte[] retoCifrado = (byte[]) in.readObject();
            int reto = descifrarRSA(retoCifrado); // Implementa descifrarRSA en el cliente
            out.writeInt(reto);

            // Paso 3: Verificar respuesta del servidor
            if (!"OK".equals(in.readUTF())) {
                System.out.println("Autenticación fallida");
                return;
            }

            // Paso 4: Recibir P, G y G^x
            BigInteger P = (BigInteger) in.readObject();
            BigInteger G = (BigInteger) in.readObject();
            BigInteger Gx = (BigInteger) in.readObject();

            // Paso 5: Calcular G^y y enviar al servidor
            Random random = new Random();
            BigInteger y = new BigInteger(1024, random);
            BigInteger Gy = G.modPow(y, P);
            out.writeObject(Gy);

            // Calcular clave compartida G^(xy)
            BigInteger sharedSecret = Gx.modPow(y, P);
            MessageDigest sha512 = MessageDigest.getInstance("SHA-512");
            byte[] sharedSecretBytes = sha512.digest(sharedSecret.toByteArray());

            SecretKey K_AB1 = new SecretKeySpec(Arrays.copyOfRange(sharedSecretBytes, 0, 32), "AES");
            SecretKey K_AB2 = new SecretKeySpec(Arrays.copyOfRange(sharedSecretBytes, 32, 64), "HmacSHA384");

            // Paso 6: Enviar datos cifrados con HMAC
            String uid = "cliente" + clienteId;
            byte[] uidCifrado = cifrarAES(uid.getBytes(), K_AB1);
            byte[] uidHMAC = generarHMAC(uidCifrado, K_AB2);

            out.writeObject(uidCifrado);
            out.writeObject(uidHMAC);

            // Paso 7: Recibir confirmación final del servidor
            if ("OK".equals(in.readUTF())) {
                System.out.println("Protocolo completado exitosamente para el cliente " + clienteId);
            } else {
                System.out.println("Error en la verificación final.");
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private byte[] cifrarAES(byte[] data, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        byte[] iv = new byte[16];
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
        return cipher.doFinal(data);
    }

    private byte[] generarHMAC(byte[] data, SecretKey key) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA384");
        mac.init(key);
        return mac.doFinal(data);
    }

    private int descifrarRSA(byte[] mensajeCifrado) throws Exception {
        // Implementa descifrado RSA en el cliente (necesita clave privada)
        return 0;
    }
}
