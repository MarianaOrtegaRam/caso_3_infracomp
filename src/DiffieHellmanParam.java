import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class DiffieHellmanParam {

    public static BigInteger[] generatePG(String opensslPath) throws Exception {
        // Usa ProcessBuilder en lugar de Runtime.getRuntime().exec(...)
        ProcessBuilder processBuilder = new ProcessBuilder(opensslPath + "openssl", "dhparam", "-text", "1024");
        Process process = processBuilder.start();

        BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
        StringBuilder output = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            output.append(line).append("\n");
        }
        reader.close();
        process.waitFor();

        BigInteger p = parseBigInteger(output.toString(), "prime:");
        BigInteger g = parseBigInteger(output.toString(), "generator:");

        return new BigInteger[]{p, g};
    }

    private static BigInteger parseBigInteger(String output, String label) {
        Pattern pattern = Pattern.compile(label + "\\s*([0-9A-F]+)", Pattern.CASE_INSENSITIVE);
        Matcher matcher = pattern.matcher(output);
        if (matcher.find()) {
            return new BigInteger(matcher.group(1), 16);
        } else {
            throw new RuntimeException("No se encontró " + label + " en la salida de OpenSSL.");
        }
    }
}
