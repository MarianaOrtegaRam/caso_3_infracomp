import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.Cipher;

public class Asimetrico {
	
	public static byte[] cifrar(Key llave, String algoritmo, String texto) {
		byte[] textoCifrado;
		
		try {
			Cipher cifrador = Cipher.getInstance(algoritmo);
			byte[] textoClaro = texto.getBytes();
			
			cifrador.init(Cipher.ENCRYPT_MODE, llave);
			textoCifrado = cifrador.doFinal(textoClaro);
			
			return textoCifrado;
		} catch (Exception e) {
			System.out.println("Exception: " + e.getMessage());
			return null;
		}
	}
	
	public static byte[] descifrar(Key llave, String algoritmo, byte[] texto) {
		byte[] textoClaro;
		
		try {
			Cipher cifrador = Cipher.getInstance(algoritmo);
			cifrador.init(Cipher.DECRYPT_MODE, llave);
			textoClaro = cifrador.doFinal(texto);
		} catch (Exception e) {
			System.out.println("Exception: " + e.getMessage());
			return null;
		}
		return textoClaro;
	}


    public static void main(String[] args) throws NoSuchAlgorithmException {
		String textoAsim = "hola";
		KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
		generator.initialize(1024);
		KeyPair keyPair = generator.generateKeyPair();
		PublicKey publica = keyPair.getPublic();
		PrivateKey privada = keyPair.getPrivate();
		

		byte[] cifradoSim = cifrar(publica, "RSA", textoAsim);
		System.out.println("Texto cifrado: " + cifradoSim);
		
		byte[] descifradoSim = descifrar(privada, "RSA", cifradoSim);
		String descifradoClaro = new String(descifradoSim, StandardCharsets.UTF_8);
		System.out.println("Texto descifrado: " + descifradoClaro);
	}


}

