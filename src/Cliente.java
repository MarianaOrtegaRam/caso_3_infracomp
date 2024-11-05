
public class Cliente {
    public static void main(String[] args) {
        while (true) {
            try {
                System.out.println("Numero de clientes:");
                System.out.println("1. Unico iterativo");
                System.out.println("2. 4 clientes concurrentes");
                System.out.println("3. 8 clientes concurrentes");
                System.out.println("4. 32 clientes concurrentes");
                int numClientes = Integer.parseInt(System.console().readLine());

                switch (numClientes) {
                    case 1:
                        ThreadCliente clienteUnico = new ThreadCliente(true);
                        clienteUnico.start();
                        break;
                    case 2:
                        for (int i = 0; i < 4; i++) {
                            ThreadCliente cliente = new ThreadCliente(false);
                            cliente.start();
                        }
                        break;
                    case 3:
                        for (int i = 0; i < 8; i++) {
                            ThreadCliente cliente = new ThreadCliente(false);
                            cliente.start();
                        }
                        break;
                    case 4:
                        for (int i = 0; i < 32; i++) {
                            ThreadCliente cliente = new ThreadCliente(false);
                            cliente.start();
                        }
                        break;
                    default:
                        System.out.println("Opcion no valida");
                        break;
                }
            } catch (Exception e) {
                System.out.println("Error: " + e.getMessage());
            }
        }
    }
}
