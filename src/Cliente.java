import java.util.Scanner;

public class Cliente {
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

        System.out.print("Ingrese el número de clientes concurrentes: ");
        int numClientes = scanner.nextInt();
        scanner.close();

        for (int i = 0; i < numClientes; i++) {
            new Thread(new ClienteRunnable(i + 1)).start();
        }
    }
}