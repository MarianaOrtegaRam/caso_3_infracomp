import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;

public class Servidor {
    private static final int PORT = 12345;
    private static Map<String, Paquete> tablaPaquetes = new HashMap<>();
    private static PrivateKey privateKey;
    private static PublicKey publicKey;

    public static void main(String[] args) {
        generarLlavesRSA(); // Generar y almacenar llaves RSA
        cargarTablaPaquetes(); // Cargar la tabla con los 32 paquetes predeterminados
        
        try (ServerSocket serverSocket = new ServerSocket(PORT)) {
            System.out.println("Servidor iniciado en el puerto " + PORT);
            while (true) {
                Socket clientSocket = serverSocket.accept();
                new ThreadServidor(clientSocket, tablaPaquetes, privateKey, publicKey).start();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void generarLlavesRSA() {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(1024);
            KeyPair pair = keyGen.generateKeyPair();
            privateKey = pair.getPrivate();
            publicKey = pair.getPublic();
            System.out.println("Llaves RSA generadas.");
            // Puedes agregar código para guardar las llaves en archivos si es necesario.
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void cargarTablaPaquetes() {
        // Cargar los 32 paquetes en la tabla con su estado inicial
        tablaPaquetes.put("cliente1_paquete1", new Paquete(Paquete.ENOFICINA));
        tablaPaquetes.put("cliente2_paquete2", new Paquete(Paquete.RECOGIDO));
        // Agrega los demás paquetes según sea necesario para completar los 32.
        System.out.println("Tabla de paquetes cargada.");
    }
}
