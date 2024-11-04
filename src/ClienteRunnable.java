import java.io.*;
import java.math.BigInteger;
import java.net.Socket;
import java.security.*;
import java.util.Arrays;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class ClienteRunnable implements Runnable {
    private String usuarioId;
    private String paqueteId;
    private static final String SERVIDOR_HOST = "localhost";
    private static final int PUERTO_SERVIDOR = 1234;

    public ClienteRunnable(String usuarioId, String paqueteId) {
        this.usuarioId = usuarioId;
        this.paqueteId = paqueteId;
    }

    public void run() {
        try (Socket socket = new Socket("localhost", 1234);
         ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
         ObjectInputStream in = new ObjectInputStream(socket.getInputStream())) {

            System.out.println("Cliente conectado al servidor en " + SERVIDOR_HOST + ":" + PUERTO_SERVIDOR);

            out.writeObject("SECINIT");

            byte[] desafioEncriptado = (byte[]) in.readObject();
            byte[] desafioDescifrado = descifrarConLlavePublica(desafioEncriptado);
            System.out.println("Desafío recibido y descifrado.");

            BigInteger G = new BigInteger("2");
            BigInteger P = new BigInteger("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
                                          + "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
                                          + "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
                                          + "E485B576625E7EC6F44C42E9A63A36210000000000090563", 16);
            BigInteger secretoCliente = new BigInteger(512, new SecureRandom());
            BigInteger Gy = G.modPow(secretoCliente, P);
            out.writeObject(Gy);

            BigInteger Gx = (BigInteger) in.readObject();
            BigInteger secretoCompartido = Gx.modPow(secretoCliente, P);

            MessageDigest sha512 = MessageDigest.getInstance("SHA-512");
            byte[] digest = sha512.digest(secretoCompartido.toByteArray());
            SecretKey llaveAES = new SecretKeySpec(Arrays.copyOfRange(digest, 0, 32), "AES");
            SecretKey llaveHMAC = new SecretKeySpec(Arrays.copyOfRange(digest, 32, 64), "HMACSHA384");

            String uid = usuarioId + "-" + paqueteId;
            byte[] uidCifrado = cifrarConAES(uid.getBytes(), llaveAES);
            byte[] hmac = generarHMAC(uidCifrado, llaveHMAC);

            out.writeObject(uidCifrado);
            out.writeObject(hmac);
            System.out.println("UID cifrado y HMAC enviados al servidor.");

            String respuesta = (String) in.readObject();
            System.out.println("Respuesta del servidor: " + respuesta);

        } catch (IOException e) {
            System.err.println("Error de conexión: " + e.getMessage());
            e.printStackTrace();
        } finally {
            try {
                if (socket != null && !socket.isClosed()) {
                    socket.close();
                }
            } catch (IOException e) {
                System.err.println("Error cerrando el socket: " + e.getMessage());
            }
        }
    }

    private byte[] cifrarConAES(byte[] datos, SecretKey llaveAES) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        cipher.init(Cipher.ENCRYPT_MODE, llaveAES, new IvParameterSpec(iv));
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(iv);
        outputStream.write(cipher.doFinal(datos));
        return outputStream.toByteArray();
    }

    private byte[] generarHMAC(byte[] datos, SecretKey llaveHMAC) throws Exception {
        Mac hmac = Mac.getInstance("HmacSHA384");
        hmac.init(llaveHMAC);
        return hmac.doFinal(datos);
    }
}
