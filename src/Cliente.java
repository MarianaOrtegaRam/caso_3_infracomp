import java.io.IOException;
import java.net.Socket;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class Cliente {
    public static void main(String[] args) {
        ExecutorService executor = Executors.newFixedThreadPool(10);
        try {
            Socket socket = new Socket("localhost", 1234);
            System.out.println("Cliente conectado al servidor en localhost:1234");
            executor.submit(new ClienteRunnable(socket));
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            executor.shutdown();
        }
    }
}
