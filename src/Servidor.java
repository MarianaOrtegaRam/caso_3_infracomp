import java.io.*;
import java.net.*;

public class Servidor {
    private static final int PUERTO = 1234;

    public static void main(String[] args) {
        try (ServerSocket serverSocket = new ServerSocket(PUERTO)) {
            System.out.println("Servidor iniciado y esperando conexiones en el puerto " + PUERTO);

            while (true) {
                try {
                    Socket socket = serverSocket.accept();
                    System.out.println("Cliente conectado.");
                    new Thread(new ThreadServidor(socket)).start();
                } catch (IOException e) {
                    System.err.println("Error al aceptar una conexión: " + e.getMessage());
                }
            }
        } catch (IOException e) {
            System.err.println("Error al iniciar el servidor: " + e.getMessage());
        }
    }
}
