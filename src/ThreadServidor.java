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
            String message = (String) in.readObject();
            if ("SECINIT".equals(message)) {
                // Step 2a and 2b: Process challenge/response as per protocol
                // Assume that the challenge-response logic is implemented here
                
                out.writeObject("OK"); // or "ERROR" based on verification
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
