import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Map;

public class ThreadServidor extends Thread {
    private Socket socket;
    private Map<String, Paquete> tablaPaquetes;
    private PrivateKey privateKey;
    private PublicKey publicKey;

    public ThreadServidor(Socket socket, Map<String, Paquete> tablaPaquetes, PrivateKey privateKey, PublicKey publicKey) {
        this.socket = socket;
        this.tablaPaquetes = tablaPaquetes;
        this.privateKey = privateKey;
        this.publicKey = publicKey;
    }

    public void run() {
        try (ObjectInputStream in = new ObjectInputStream(socket.getInputStream());
             ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream())) {

            String clienteId = in.readUTF();
            String paqueteId = in.readUTF();
            String claveConsulta = clienteId + "_" + paqueteId;

            Paquete paquete = tablaPaquetes.getOrDefault(claveConsulta, new Paquete(Paquete.DESCONOCIDO));
            String estado = paquete.getEstado();

            out.writeUTF(estado);
            out.flush();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
