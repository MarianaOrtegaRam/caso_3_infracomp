import java.io.*;
import java.net.*;
import java.security.*;
import java.util.Base64;
import javax.crypto.*;

public class Cliente {
    private static final String HOST = "localhost";
    private static final int PUERTO = 1234;

    public static void main(String[] args) {
        try {
            Socket socket = new Socket(HOST, PUERTO);
            System.out.println("Cliente conectado al servidor en " + HOST + ":" + PUERTO);

            new Thread(new ClienteRunnable(socket)).start();
        } catch (IOException e) {
            System.err.println("Error al conectar al servidor: " + e.getMessage());
        }
    }
}

class ClienteRunnable implements Runnable {
    private final Socket socket;

    public ClienteRunnable(Socket socket) {
        this.socket = socket;
    }

    @Override
    public void run() {
        try (ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
             ObjectInputStream in = new ObjectInputStream(socket.getInputStream())) {

            // Ejemplo de clave secreta compartida (debe coincidir con el servidor)
            SecretKey secretKey = generarClaveSecreta();

            // Ejemplo de envío de mensaje cifrado
            String mensaje = "Mensaje seguro del cliente";
            enviarMensajeCifrado(out, mensaje, secretKey);

            // Ejemplo de recepción y descifrado
            String mensajeRecibido = recibirMensajeCifrado(in, secretKey);
            System.out.println("Mensaje recibido del servidor: " + mensajeRecibido);

        } catch (IOException | GeneralSecurityException | ClassNotFoundException e) {
            System.err.println("Error en la comunicación con el servidor: " + e.getMessage());
        } finally {
            try {
                if (socket != null && !socket.isClosed()) {
                    socket.close();
                    System.out.println("Socket cerrado.");
                }
            } catch (IOException e) {
                System.err.println("Error al cerrar el socket: " + e.getMessage());
            }
        }
    }

    private SecretKey generarClaveSecreta() throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128);
        return keyGen.generateKey();
    }

    private void enviarMensajeCifrado(ObjectOutputStream out, String mensaje, SecretKey key)
            throws IOException, GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] mensajeCifrado = cipher.doFinal(mensaje.getBytes());
        out.writeObject(Base64.getEncoder().encodeToString(mensajeCifrado));
    }

    private String recibirMensajeCifrado(ObjectInputStream in, SecretKey key)
            throws IOException, GeneralSecurityException, ClassNotFoundException {
        String mensajeCifrado = (String) in.readObject();
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] mensajeDescifrado = cipher.doFinal(Base64.getDecoder().decode(mensajeCifrado));
        return new String(mensajeDescifrado);
    }
}
