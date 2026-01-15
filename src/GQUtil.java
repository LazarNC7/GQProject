import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class GQUtil {

    // Simuleaza functia de redundanta Red(I) -> J
    public static BigInteger computeJ(String identity, BigInteger n) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(identity.getBytes());
            // In practica, se adauga padding specific (ISO 9796), momentan folosim hash mod n
            return new BigInteger(1, hash).mod(n);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Eroare Hashing", e);
        }
    }

    // Calculeaza intrebarea d = h(M, T) conform protocolului non-interactiv
    public static BigInteger computeD(String message, BigInteger T, BigInteger v) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(message.getBytes());
            md.update(T.toByteArray());
            byte[] hash = md.digest();
            // d trebuie sa fie in intervalul [0, v-1]
            return new BigInteger(1, hash).mod(v);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Eroare Hashing", e);
        }
    }
}