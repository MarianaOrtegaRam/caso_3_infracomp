import java.io.*;
import java.math.BigInteger;
import java.net.Socket;
import java.security.*;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class ThreadServidor extends Thread {
    private Socket clientSocket;
    private PrivateKey privateKey;
    private static final Map<String, Integer> tablaPaquetes = Servidor.getPackageTable();

    public ThreadServidor(Socket socket, PrivateKey privateKey) {
        this.clientSocket = socket;
        this.privateKey = privateKey;
    }

    public void run() {
        try (ObjectInputStream in = new ObjectInputStream(clientSocket.getInputStream());
             ObjectOutputStream out = new ObjectOutputStream(clientSocket.getOutputStream())) {

            SecureRandom random = new SecureRandom();
            byte[] challenge = new byte[16];
            random.nextBytes(challenge);

            // Cifra el desafío con la clave privada
            out.writeObject(cifrarConLlavePrivada(challenge));

            BigInteger G = new BigInteger("2");
            BigInteger P = new BigInteger("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
                                          + "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
                                          + "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
                                          + "E485B576625E7EC6F44C42E9A63A36210000000000090563", 16);
            BigInteger secretoServidor = new BigInteger(512, random);
            BigInteger Gx = G.modPow(secretoServidor, P);
            out.writeObject(P);
            out.writeObject(G);
            out.writeObject(Gx);

            BigInteger Gy = (BigInteger) in.readObject();
            BigInteger secretoCompartido = Gy.modPow(secretoServidor, P);

            MessageDigest sha512 = MessageDigest.getInstance("SHA-512");
            byte[] digest = sha512.digest(secretoCompartido.toByteArray());
            SecretKey llaveAES = new SecretKeySpec(Arrays.copyOfRange(digest, 0, 32), "AES");
            SecretKey llaveHMAC = new SecretKeySpec(Arrays.copyOfRange(digest, 32, 64), "HMACSHA384");

            String uid = decryptAndVerify(in, llaveAES, llaveHMAC);
            int status = tablaPaquetes.getOrDefault(uid, -1);

            if (status == -1) {
                out.writeObject("DESCONOCIDO");
            } else {
                out.writeObject("Estado: " + getStatusText(status));
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private String decryptAndVerify(ObjectInputStream in, SecretKey aesKey, SecretKey hmacKey) throws Exception {
        // Recibir el UID cifrado y el HMAC del cliente
        byte[] uidCifrado = (byte[]) in.readObject();
        byte[] hmacRecibido = (byte[]) in.readObject();
    
        // Verificar el HMAC
        Mac hmac = Mac.getInstance("HmacSHA384");
        hmac.init(hmacKey);
        byte[] hmacCalculado = hmac.doFinal(uidCifrado);
    
        // Comparar el HMAC recibido con el calculado
        if (!Arrays.equals(hmacRecibido, hmacCalculado)) {
            throw new SecurityException("HMAC no coincide, mensaje alterado.");
        }
    
        // Extraer el IV del mensaje cifrado
        byte[] iv = Arrays.copyOfRange(uidCifrado, 0, 16);
        byte[] datosCifrados = Arrays.copyOfRange(uidCifrado, 16, uidCifrado.length);
    
        // Descifrar el UID
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, aesKey, new IvParameterSpec(iv));
        byte[] uidDescifrado = cipher.doFinal(datosCifrados);
    
        // Convertir el UID descifrado a String y retornarlo
        return new String(uidDescifrado);
    }
    
    private byte[] cifrarConLlavePrivada(byte[] datos) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);
        return cipher.doFinal(datos);
    }

    private String getStatusText(int status) {
        switch (status) {
            case 0: return "ENOFICINA";
            case 1: return "RECOGIDO";
            case 2: return "ENCLASIFICACION";
            case 3: return "DESPACHADO";
            case 4: return "ENENTREGA";
            case 5: return "ENTREGADO";
            default: return "DESCONOCIDO";
        }
    }
}
