import java.io.*;
import java.net.*;
import java.util.HashMap;

public class Servidor {
    private static final int PORT = 12345;
    private static final HashMap<String, PackageInfo> packagesTable = new HashMap<>();

    public static void main(String[] args) {
        // Generate or load keys
        try {
            ServerSocket serverSocket = new ServerSocket(PORT);
            System.out.println("Server is running on port " + PORT);

            // Initialize the package table
            initializePackagesTable();

            while (true) {
                Socket clientSocket = serverSocket.accept();
                System.out.println("New client connected.");
                new ThreadServidor(clientSocket, packagesTable).start();
            }
        } catch (IOException e) {
            System.out.println("Server error: " + e.getMessage());
        }
    }

    private static void initializePackagesTable() {
        // Populate table with sample data
        for (int i = 0; i < 32; i++) {
            packagesTable.put("client" + i, new PackageInfo("package" + i, "ENOFICINA"));
        }
    }
}

class PackageInfo {
    String packageId;
    String status;

    public PackageInfo(String packageId, String status) {
        this.packageId = packageId;
        this.status = status;
    }
}
