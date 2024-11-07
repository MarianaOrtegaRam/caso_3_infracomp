import java.io.*;
import java.math.BigInteger;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.ArrayList;
import java.util.HashMap;
import javax.crypto.*;
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class ThreadServidor extends Thread {
    private final Socket clientSocket;
    private final HashMap<String, ArrayList<PackageInfo>> packagesTable;
    private final PrivateKey privateKey;

    public ThreadServidor(Socket socket, HashMap<String, ArrayList<PackageInfo>> packagesTable, KeyPair serverKeyPair) {
        this.clientSocket = socket;
        this.packagesTable = packagesTable;
        this.privateKey = serverKeyPair.getPrivate();
    }

    public void run() {
        try (ObjectOutputStream out = new ObjectOutputStream(clientSocket.getOutputStream());
                ObjectInputStream in = new ObjectInputStream(clientSocket.getInputStream())) {

            // Paso 1: Recibir "SECINIT" y responder con "OK"
            String mensajeCliente = (String) in.readObject();
            System.out.println("Servidor: Recibió " + mensajeCliente);
            if ("SECINIT".equals(mensajeCliente)) {
                out.writeObject("OK");
                out.flush();
                System.out.println("Servidor: Envió OK");
            } else {
                System.out.println("Servidor: Mensaje inesperado recibido. Enviando ERROR y cerrando conexión.");
                out.writeObject("ERROR");
                out.flush();
                clientSocket.close();
                return;
            }

            // Paso 2: Recibir desafío cifrado del cliente
            byte[] encryptedR = (byte[]) in.readObject();

            // Paso 3: Descifrar el desafío R usando la llave privada del servidor

            ///CASO 4:PARTE SIMETRICA
            long startTime1 = System.nanoTime();

            byte[] R = decryptWithPrivateKey(encryptedR, privateKey);
            System.out.println("Servidor: Desafío recibido y descifrado correctamente.");

            long endTime1 = System.nanoTime();
            long executionTimeNanoseconds = endTime1 - startTime1;
            double executionTimeMilliseconds1 = executionTimeNanoseconds / 1000000.0;
            // FIN CASO 4 PARTE SIMETRICA
            // Enviar RTA (que es el mismo R) de vuelta al cliente
            out.writeObject(R);
            out.flush();
            System.out.println("Servidor: Enviado RTA al cliente");

            // Paso 6: Esperar confirmación del cliente
            String response = (String) in.readObject();
            if ("OK".equals(response)) {
                System.out.println("Servidor: Cliente ha confirmado la verificación con OK.");
            } else {
                System.out.println("Servidor: Verificación fallida, cerrando conexión.");
            }

            // Paso 7: Generar G, P y G^x (con un primo de 1024 bits)

            // Generar G
            long startTimeG = System.nanoTime();
            BigInteger G = new BigInteger("2"); // Generador comúnmente usado
            long endTimeG = System.nanoTime();
            long executionTimeNanosecondsG = endTimeG - startTimeG;
            double executionTimeMillisecondsG = executionTimeNanosecondsG / 1000000.0;

            // Generar P

            long startTimeP = System.nanoTime();
            BigInteger P = new BigInteger("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
                    + "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
                    + "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
                    + "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
                    + "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
                    + "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
                    + "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
                    + "670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF", 16);

            long endTimeP = System.nanoTime();
            long executionTimeNanosecondsP = endTimeP - startTimeP;
            double executionTimeMillisecondsP = executionTimeNanosecondsP / 1000000.0;

            // Generar G^x

            long startTimeGx = System.nanoTime();
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH");
            DHParameterSpec dhParamSpec = new DHParameterSpec(P, G);
            keyGen.initialize(dhParamSpec);
            KeyPair dhKeyPair = keyGen.generateKeyPair();
            BigInteger Gx = ((DHPublicKey) dhKeyPair.getPublic()).getY();
            long endTimeGx = System.nanoTime();
            long executionTimeNanosecondsGx = endTimeGx - startTimeGx;
            double executionTimeMillisecondsGx = executionTimeNanosecondsGx / 1000000.0;

            // Enviar G, P y G^x al cliente
            out.writeObject(G);
            out.writeObject(P);
            out.writeObject(Gx);
            out.flush();
            System.out.println("Servidor: Envió G, P y G^x");

            // Paso 11a: Recibir G^y del cliente y calcular la clave compartida
            BigInteger Gy = (BigInteger) in.readObject();
            BigInteger sharedSecret = Gy.modPow(((DHPrivateKey) dhKeyPair.getPrivate()).getX(), P);
            System.out
                    .println("Servidor: Clave secreta compartida derivada: " + bytesToHex(sharedSecret.toByteArray()));

            // Derivar claves AES y HMAC a partir de la clave compartida
            byte[] secretBytes = sha512(sharedSecret.toByteArray());
            SecretKey K_AB1 = new SecretKeySpec(secretBytes, 0, 32, "AES");
            SecretKey K_AB2 = new SecretKeySpec(secretBytes, 32, 32, "HmacSHA384");

            // Depuración: Imprimir claves derivadas
            System.out.println("Servidor: Clave AES derivada: " + bytesToHex(K_AB1.getEncoded()));
            System.out.println("Servidor: Clave HMAC derivada: " + bytesToHex(K_AB2.getEncoded()));

            // Paso 12: Enviar IV al cliente
            IvParameterSpec iv = new IvParameterSpec(generateRandomIV());
            out.writeObject(iv.getIV());
            out.flush();
            System.out.println("Servidor: Envió IV: " + bytesToHex(iv.getIV()));

            // caso 3
            long startTimeVE = System.nanoTime();

            // Paso 4: Recibir ID de usuario y HMAC
            byte[] encryptedUserId = (byte[]) in.readObject();
            byte[] hmacUserId = (byte[]) in.readObject();
            System.out.println("Servidor: Recibido ID de usuario cifrado y HMAC");

            // Verificar y descifrar el ID de usuario...
            byte[] decryptedUserId = decryptAES(encryptedUserId, K_AB1, iv);
            String decryptedUserIdStr = new String(decryptedUserId, StandardCharsets.UTF_8);
            byte[] hmacUserIDLocal = generateHMAC(decryptedUserIdStr, K_AB2);

            if (!MessageDigest.isEqual(hmacUserId, hmacUserIDLocal)) {
                System.out.println("No fue correcta la verificación. Cerrando conexión...");
                // Cerrar el socket del cliente para finalizar la conexión
                try {
                    clientSocket.close();
                } catch (IOException e) {
                    System.out.println("Error al cerrar el socket: " + e.getMessage());
                }
                return; // Opcionalmente, termina el método 'run' o la ejecución del hilo
            }
            System.out.println("Verificación HMAC exitosa. Procediendo...");

            // Paso 5: Recibir ID de paquete y HMAC
            byte[] encryptedPackageId = (byte[]) in.readObject();
            byte[] hmacPackageId = (byte[]) in.readObject();
            System.out.println("Servidor: Recibido ID de paquete cifrado y HMAC");

            byte[] decryptedPaqueteId = decryptAES(encryptedPackageId, K_AB1, iv);
            String decryptedPaqueteIdStr = new String(decryptedPaqueteId, StandardCharsets.UTF_8);
            byte[] hmacPaqueteIDLocal = generateHMAC(decryptedPaqueteIdStr, K_AB2);

            if (!MessageDigest.isEqual(hmacPackageId, hmacPaqueteIDLocal)) {
                System.out.println("No fue correcta la verificación. Cerrando conexión...");
                // Cerrar el socket del cliente para finalizar la conexión
                try {
                    clientSocket.close();
                } catch (IOException e) {
                    System.out.println("Error al cerrar el socket: " + e.getMessage());
                }
                return; // Opcionalmente, termina el método 'run' o la ejecución del hilo
            }
            System.out.println("Verificación HMAC exitosa. Procediendo...");

            long endTimeVE = System.nanoTime();
            long executionTimeNanosecondsVE = endTimeVE - startTimeVE;
            double executionTimeMillisecondsVE = executionTimeNanosecondsVE / 1000000.0;
            ///termina caso 3
            // Paso 6: Enviar estado del paquete cifrado y HMAC
            String packageStatus = buscarEstadoDelPaquete(decryptedUserIdStr, decryptedPaqueteIdStr);
            byte[] encryptedPackageStatus = encryptAES(packageStatus, K_AB1, iv);
            byte[] hmacPackageStatus = generateHMAC(packageStatus, K_AB2);

            out.writeObject(encryptedPackageStatus);
            out.writeObject(hmacPackageStatus);
            out.flush();
            System.out.println("Servidor: Enviado estado del paquete cifrado y HMAC");

            /// Confirmación de terminación
            String finalizar = (String) in.readObject();
            if ("TERMINAR".equals(finalizar)) {
                System.out.println("Servidor: Protocolo completado con éxito, cerrando conexión.");
                System.out.println(
                        "Tiempo de ejecución responder el reto : " + executionTimeMilliseconds1 + " millisegundos");
                System.out.println(
                        "Tiempo de ejecución generar G : " + executionTimeMillisecondsG + " millisegundos");
                System.out.println(
                        "Tiempo de ejecución generar P : " + executionTimeMillisecondsP + " millisegundos");
                System.out.println(
                        "Tiempo de ejecución generar G^x : " + executionTimeMillisecondsGx + " millisegundos");

                System.err.println(
                        "Tiempo de ejecución parte simétrica: " + executionTimeMilliseconds1 + " millisegundos");
                System.err.println(
                        "Tiempo de ejecución verificar la consulta: " + executionTimeMillisecondsVE
                                + " millisegundos");
            }
        } catch (BadPaddingException e) {
            System.out.println("Error en desencriptación: Verifica que la clave e IV coincidan.");
        } catch (SocketException e) {
            System.out.println("Servidor: El cliente cerró la conexión.");
        } catch (Exception e) {
            System.out.println("Error al manejar el cliente: " + e.getMessage());
            e.printStackTrace();
        } finally {
            try {
                clientSocket.close();
            } catch (IOException e) {
                System.out.println("Error al cerrar el socket del cliente.");
            }
        }
    }

    // Método auxiliar para convertir bytes a formato hexadecimal
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    // Método auxiliar para generar el hash SHA-512 de un array de bytes
    private static byte[] sha512(byte[] input) throws NoSuchAlgorithmException {
        MessageDigest sha512 = MessageDigest.getInstance("SHA-512");
        return sha512.digest(input);
    }

    // Método auxiliar para generar un IV aleatorio de 16 bytes
    private static byte[] generateRandomIV() {
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        return iv;
    }

    // Métodos de descifrado y HMAC
    private byte[] decryptAES(byte[] encryptedData, SecretKey key, IvParameterSpec iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key, iv);
        return cipher.doFinal(encryptedData);
    }

    private byte[] generateHMAC(String data, SecretKey key) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA384");
        mac.init(key);
        return mac.doFinal(data.getBytes("UTF-8"));
    }

    private String buscarEstadoDelPaquete(String userId, String packageId) {
        // Verifica si el paquete es nulo
        if (packageId == null) {
            System.out.println("El packageId es null, devolviendo DESCONOCIDO");
            return "DESCONOCIDO";
        }

        // Obtiene la lista de paquetes del usuario
        ArrayList<PackageInfo> listaPaquetes = packagesTable.get(userId);
        if (listaPaquetes == null) {
            System.out.println("Usuario no encontrado en el HashMap, devolviendo DESCONOCIDO");
            return "DESCONOCIDO";
        } else {
            int x = 0;
            boolean encontrado = false;
            // Bucle para recorrer la lista de paquetes
            while (x < listaPaquetes.size() && !encontrado) {
                PackageInfo paquete = listaPaquetes.get(x);
                String id_paquete = paquete.getPackageId();

                // Imprime el ID del paquete actual
                System.out.println("Revisando paquete con ID: " + id_paquete);

                // Compara el ID del paquete
                if (packageId.equals(id_paquete)) {
                    encontrado = true;
                    System.out.println("Paquete encontrado, devolviendo estado: " + statusString(paquete.getStatus()));
                    return statusString(paquete.getStatus());
                }
                x++;
            }
        }
        // Si no se encontró, devuelve DESCONOCIDO
        System.out.println("Paquete no encontrado, devolviendo DESCONOCIDO");
        return "DESCONOCIDO";
    }

    // Métodos de cifrado y HMAC
    private byte[] encryptAES(String data, SecretKey key, IvParameterSpec iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        return cipher.doFinal(data.getBytes("UTF-8"));
    }

    private byte[] decryptWithPrivateKey(byte[] data, PrivateKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(data);
    }

    public String statusString(int status) {

        switch (status) {
            case 1:
                return "ENOFICINA";
            case 2:
                return "RECOGIDO";
            case 3:
                return "ENCLASIFICACION";
            case 4:
                return "DESPACHADO";
            case 5:
                return "ENENTREGA";
            default:
                return "ENTREGADO";
        }
    }
}
