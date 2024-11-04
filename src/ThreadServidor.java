import java.io.*;
import java.net.*;
import java.util.HashMap;

public class ThreadServidor extends Thread {
    private final Socket clientSocket;
    private final HashMap<String, PackageInfo> packagesTable;

    public ThreadServidor(Socket socket, HashMap<String, PackageInfo> packagesTable) {
        this.clientSocket = socket;
        this.packagesTable = packagesTable;
    }

    public void run() {
        try (ObjectOutputStream out = new ObjectOutputStream(clientSocket.getOutputStream());
             ObjectInputStream in = new ObjectInputStream(clientSocket.getInputStream())) {

            String clientId = (String) in.readObject();
            String packageId = (String) in.readObject();

            PackageInfo packageInfo = packagesTable.getOrDefault(clientId, new PackageInfo(packageId, "DESCONOCIDO"));
            out.writeObject(packageInfo.status);

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
