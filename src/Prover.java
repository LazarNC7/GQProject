import java.math.BigInteger;
import java.security.SecureRandom;

public class Prover {
    private final String identity;
    private final BigInteger B; // Secretul cardului
    private final BigInteger n; // Parametru public
    private final BigInteger v; // Parametru public
    private final SecureRandom random;

    public Prover(String identity, BigInteger B, BigInteger n, BigInteger v) {
        this.identity = identity;
        this.B = B;
        this.n = n;
        this.v = v;
        this.random = new SecureRandom();
    }

    // Genereaza semnatura pentru un mesaj (Non-interactiv)
    public GQSignature sign(String message) {
        // 1. Alege r aleator
        BigInteger r = new BigInteger(n.bitLength(), random).mod(n);

        // 2. Calculeaza testul T = r^v mod n
        BigInteger T = r.modPow(v, n);

        // 3. Calculeaza intrebarea d = h(M, T) (Non-interactivitate)
        BigInteger d = GQUtil.computeD(message, T, v);

        // 4. Calculeaza martorul t = r * B^d mod n
        BigInteger t = r.multiply(B.modPow(d, n)).mod(n);

        // Returneaza pachetul semnaturii (Appendix)
        return new GQSignature(identity, d, t);
    }
}