import java.io.*;
import java.net.*;

public class Cliente{
    private static final String SERVER_ADDRESS = "localhost";
    private static final int SERVER_PORT = 12345;

    public static void main(String[] args) {
        try (Socket socket = new Socket(SERVER_ADDRESS, SERVER_PORT);
             ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
             ObjectInputStream in = new ObjectInputStream(socket.getInputStream())) {

            String clientId = "client0";  // example client ID
            String packageId = "package0";  // example package ID
            out.writeObject(clientId);
            out.writeObject(packageId);

            String response = (String) in.readObject();
            System.out.println("Package Status: " + response);

        } catch (Exception e) {
            System.out.println("Client error: " + e.getMessage());
        }
    }
}
