import java.math.BigInteger;
import java.security.SecureRandom;

public class TrustedAuthority {
    private final BigInteger n; // Modulul public
    private final BigInteger v; // Exponentul public
    private final BigInteger p; // Secret
    private final BigInteger q; // Secret
    private final SecureRandom random;

    public TrustedAuthority(int keySize, int publicExponent) {
        this.random = new SecureRandom();
        this.p = BigInteger.probablePrime(keySize / 2, random);
        this.q = BigInteger.probablePrime(keySize / 2, random);
        this.n = p.multiply(q);
        this.v = BigInteger.valueOf(publicExponent);
    }

    // Emite secretul B pentru un utilizator
    // B = J^(-1/v) mod n
    public BigInteger generateCardSecret(String identity) {
        BigInteger J = GQUtil.computeJ(identity, n);

        // Calculul Phi(n) = (p-1)(q-1)
        BigInteger phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));

        // Calcul exponent privat: -1/v mod phi
        // B^v * J = 1 (mod n) => B = (J^-1)^(1/v)
        BigInteger invV = v.modInverse(phi);
        BigInteger invJ = J.modInverse(n);

        return invJ.modPow(invV, n);
    }

    public BigInteger getN() { return n; }
    public BigInteger getV() { return v; }
}