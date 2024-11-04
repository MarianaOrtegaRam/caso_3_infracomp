import java.io.*;
import java.net.Socket;
import java.security.*;
import java.util.*;
import javax.crypto.*;

public 
class ThreadServidor implements Runnable {
    private final Socket socket;

    public ThreadServidor(Socket socket) {
        this.socket = socket;
    }

    @Override
    public void run() {
        try (ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
             ObjectInputStream in = new ObjectInputStream(socket.getInputStream())) {

            // Ejemplo de envío de mensaje cifrado (modificar según lógica)
            String mensaje = "Mensaje seguro del servidor";
            SecretKey secretKey = generarClaveSecreta(); // Genera clave secreta
            enviarMensajeCifrado(out, mensaje, secretKey);

            // Ejemplo de recepción y descifrado
            String mensajeRecibido = recibirMensajeCifrado(in, secretKey);
            System.out.println("Mensaje recibido del cliente: " + mensajeRecibido);

        } catch (IOException | GeneralSecurityException e) {
            System.err.println("Error en la comunicación con el cliente: " + e.getMessage());
        } catch (ClassNotFoundException e) {
                    // TODO Auto-generated catch block
                    e.printStackTrace();
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
