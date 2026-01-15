import java.math.BigInteger;

// Structura de date pentru semnatura ("Appendix")
class GQSignature {
    final String identity;
    final BigInteger d;
    final BigInteger t;

    public GQSignature(String identity, BigInteger d, BigInteger t) {
        this.identity = identity;
        this.d = d;
        this.t = t;
    }
}

public class Verifier {
    private final BigInteger n;
    private final BigInteger v;

    public Verifier(BigInteger n, BigInteger v) {
        this.n = n;
        this.v = v;
    }

    public boolean verify(String message, GQSignature signature) {
        // 1. Reconstruieste J din identitate (folosind aceeasi regula de redundanta)
        BigInteger J = GQUtil.computeJ(signature.identity, n);

        // 2. Reconstruieste Testul T
        // Formula: T' = J^d * t^v mod n
        BigInteger J_pow_d = J.modPow(signature.d, n);
        BigInteger t_pow_v = signature.t.modPow(v, n);
        BigInteger T_reconstructed = J_pow_d.multiply(t_pow_v).mod(n);

        // 3. Verifica hash-ul
        // d trebuie sa fie egal cu h(M, T_reconstructed)
        BigInteger d_check = GQUtil.computeD(message, T_reconstructed, v);

        return signature.d.equals(d_check);
    }
}