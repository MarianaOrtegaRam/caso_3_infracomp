import java.io.*;
import java.net.*;
import java.security.*;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class Servidor {
    private static final int PORT = 12345;
    private static final String PUBLIC_KEY_FILE = "publicKey.ser";
    private static final String PRIVATE_KEY_FILE = "privateKey.ser";
    private static KeyPair serverKeyPair;
    private static final HashMap<String, ArrayList<PackageInfo>> packagesTable = new HashMap<>();

    public static void main(String[] args) {
        initializePackagesTable();
        for (Map.Entry<String, ArrayList<PackageInfo>> entry : packagesTable.entrySet()) {
        String userId = entry.getKey();
        ArrayList<PackageInfo> packageList = entry.getValue();

        System.out.println("Usuario ID: " + userId);
        
        if (packageList != null && !packageList.isEmpty()) {
            for (PackageInfo paquete : packageList) {
                System.out.println("  " + paquete.getPackageId() + " " + paquete.getStatus()); // Llama a toString() de PackageInfo para imprimir detalles
            }
        } else {
            System.out.println("  No hay paquetes para este usuario.");
        }
    }
        loadOrGenerateKeyPair();
        displayMenu();
    }

    private static void initializePackagesTable() {
        // Initialize package table with dummy data
        for (int j = 0; j < 8; j++) {
            ArrayList<PackageInfo> paquetes = new ArrayList<>();

            for (int i = 0; i < 32; i++){
                if (j % 10 == 0 ){
                    paquetes.add(new PackageInfo("package" + i, "ENOFICINA"));
                }
                else if ( j % 9 == 0){
                    paquetes.add(new PackageInfo("package" + i,"RECOGIDO"));
                }
                else if ( j % 8 == 0){
                    paquetes.add(new PackageInfo("package" + i, "ENCLASIFICACION"));
                }
                else if ( j % 7 == 0){
                    paquetes.add(new PackageInfo("package" + i, "DESPACHADO"));
                }
                else if ( j % 6 == 0){
                    paquetes.add(new PackageInfo("package" + i, "ENENTREGA"));
                }
                else {
                    paquetes.add(new PackageInfo("package" + i, "ENTREGADO"));
                }
            }
            packagesTable.put("client"+ j , paquetes);
        }
    }

    private static void loadOrGenerateKeyPair() {
        File publicKeyFile = new File(PUBLIC_KEY_FILE);
        File privateKeyFile = new File(PRIVATE_KEY_FILE);

        if (publicKeyFile.exists() && privateKeyFile.exists()) {
            System.out.println("Loading existing key pair...");
            try (ObjectInputStream pubIn = new ObjectInputStream(new FileInputStream(publicKeyFile));
                    ObjectInputStream privIn = new ObjectInputStream(new FileInputStream(privateKeyFile))) {
                PublicKey publicKey = (PublicKey) pubIn.readObject();
                PrivateKey privateKey = (PrivateKey) privIn.readObject();
                serverKeyPair = new KeyPair(publicKey, privateKey);
            } catch (Exception e) {
                System.out.println("Error loading key pair: " + e.getMessage());
            }
        } else {
            System.out.println("Generating new key pair...");
            try {
                KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
                keyGen.initialize(1024);
                serverKeyPair = keyGen.generateKeyPair();

                try (ObjectOutputStream pubOut = new ObjectOutputStream(new FileOutputStream(publicKeyFile));
                        ObjectOutputStream privOut = new ObjectOutputStream(new FileOutputStream(privateKeyFile))) {
                    pubOut.writeObject(serverKeyPair.getPublic());
                    privOut.writeObject(serverKeyPair.getPrivate());
                }
                System.out.println("Key pair generated and saved.");
            } catch (Exception e) {
                System.out.println("Error generating key pair: " + e.getMessage());
            }
        }
    }

    private static void displayMenu() {
        BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
        while (true) {
            System.out.println("\n--- Server Menu ---");
            System.out.println("1. Generate key pair");
            System.out.println("2. Start server and handle client requests");
            System.out.print("Choose an option: ");

            try {
                int choice = Integer.parseInt(reader.readLine());
                switch (choice) {
                    case 1:
                        loadOrGenerateKeyPair();
                        break;
                    case 2:
                        System.out.println("Choose server mode:");
                        System.out.println("1. Concurrent server");
                        System.out.println("2. Iterative server");

                        int mode = Integer.parseInt(reader.readLine());
                        switch (mode) {
                            case 1:
                                startServer(false);
                                break;
                            case 2:
                                startServer(true);
                                break;
                            default:
                                System.out.println("Invalid option. Please try again.");
                        }
                        break;
                    default:
                        System.out.println("Invalid option. Please try again.");
                }
            } catch (IOException e) {
                System.out.println("Input error: " + e.getMessage());
            }
        }
    }

    private static void startServer(boolean isIterative) {
        System.out.println("Server is running on port " + PORT + "...");
        try (ServerSocket serverSocket = new ServerSocket(PORT)) {
            while (true) {
                Socket clientSocket = serverSocket.accept();
                System.out.println("Client connected.");
                ThreadServidor threadServidor = new ThreadServidor(clientSocket, packagesTable, serverKeyPair);
                threadServidor.start();

                if (isIterative) {
                    try {
                        threadServidor.join();
                    } catch (Exception e) {
                        System.out.println("Error joining thread: " + e.getMessage());
                    }
                }
            }
        } catch (IOException e) {
            System.out.println("Server error: " + e.getMessage());
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

    public String getPackageId(){
        return packageId;
    }

    public String getStatus(){
        return status;
    }
}