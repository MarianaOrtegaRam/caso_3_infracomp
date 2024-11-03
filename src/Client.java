import java.net.Socket;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

public class Client {
    public static void main(String[] args) {
        String servidor = "localhost";
        int puerto = 12345;

        try (Socket socket = new Socket(servidor, puerto);
             ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
             ObjectInputStream in = new ObjectInputStream(socket.getInputStream())) {

            String clienteId = "cliente1";
            String paqueteId = "paquete1";

            out.writeUTF(clienteId);
            out.writeUTF(paqueteId);
            out.flush();

            String respuesta = in.readUTF();
            if (respuesta != null) {
                System.out.println("Estado del paquete: " + respuesta);
            } else {
                System.out.println("Error en la consulta");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
