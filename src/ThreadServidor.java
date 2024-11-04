import java.io.*;
import java.net.*;
import java.security.*;
import java.util.HashMap;

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

            // Follow the protocol steps as per the provided image
            // Example: Handle SECINIT and response verification
            String mensajeCliente = (String) in.readObject(); // Servidor espera "SECINIT"
            System.out.println("Servidor: Recibió " + mensajeCliente);

            if ("SECINIT".equals(mensajeCliente)) {
                out.writeObject("OK"); // Servidor responde con "OK"
                System.out.println("Servidor: Envió OK");
            } else {
                out.writeObject("ERROR");
                System.out.println("Servidor: Envió ERROR");
            }

            // Continue with further steps as per the protocol, like key generation, etc.

        } catch (Exception e) {
            System.out.println("Client handling error: " + e.getMessage());
        } finally {
            try {
                clientSocket.close();
            } catch (IOException e) {
                System.out.println("Failed to close client socket.");
            }
        }
    }
}
