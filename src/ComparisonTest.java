import java.math.BigInteger;

public class ComparisonTest {

    public static void main(String[] args) throws Exception {
        int KEY_SIZE = 1024;
        String message = "Text pentru testarea performantei semnaturii digitale";
        int ITERATIONS = 1000; // Rulăm de multe ori pentru o medie corectă

        System.out.println("=== START COMPARATIE GQ vs RSA (" + ITERATIONS + " iteratii) ===");

        // --- PREGATIRE GQ ---
        TrustedAuthority authority = new TrustedAuthority(KEY_SIZE, 65537);
        BigInteger secretB = authority.generateCardSecret("User_Test");
        Prover gqCard = new Prover("User_Test", secretB, authority.getN(), authority.getV());
        Verifier gqVerifier = new Verifier(authority.getN(), authority.getV());

        // --- PREGATIRE RSA ---
        RSABenchmark rsaBench = new RSABenchmark();
        rsaBench.setup(KEY_SIZE);
        byte[] msgBytes = message.getBytes();

        // -----------------------------------------------------
        // TEST 1: SEMNAREA
        // -----------------------------------------------------

        // Masurare GQ
        long startGQ = System.nanoTime();
        for (int i = 0; i < ITERATIONS; i++) {
            gqCard.sign(message);
        }
        long durationGQ_Sign = (System.nanoTime() - startGQ) / ITERATIONS;

        // Masurare RSA
        long startRSA = System.nanoTime();
        for (int i = 0; i < ITERATIONS; i++) {
            rsaBench.sign(msgBytes);
        }
        long durationRSA_Sign = (System.nanoTime() - startRSA) / ITERATIONS;

        // -----------------------------------------------------
        // TEST 2: VERIFICAREA
        // -----------------------------------------------------

        GQSignature gqSig = gqCard.sign(message);
        byte[] rsaSig = rsaBench.sign(msgBytes);

        // Masurare GQ
        startGQ = System.nanoTime();
        for (int i = 0; i < ITERATIONS; i++) {
            gqVerifier.verify(message, gqSig);
        }
        long durationGQ_Verif = (System.nanoTime() - startGQ) / ITERATIONS;

        // Masurare RSA
        startRSA = System.nanoTime();
        for (int i = 0; i < ITERATIONS; i++) {
            rsaBench.verify(msgBytes, rsaSig);
        }
        long durationRSA_Verif = (System.nanoTime() - startRSA) / ITERATIONS;

        // -----------------------------------------------------
        // AFISARE REZULTATE PENTRU REFERAT
        // -----------------------------------------------------

        System.out.println("\nRezultate Medii (in microsecunde - us):");
        System.out.printf("%-15s | %-15s | %-15s\n", "Algoritm", "Timp Semnare", "Timp Verificare");
        System.out.println("--------------------------------------------------");
        System.out.printf("%-15s | %-15d us | %-15d us\n", "Guillou-Quisquater", durationGQ_Sign/1000, durationGQ_Verif/1000);
        System.out.printf("%-15s | %-15d us | %-15d us\n", "RSA", durationRSA_Sign/1000, durationRSA_Verif/1000);

        System.out.println("\nDimensiuni Semnatura:");
        // Dimensiunea aproximativa pentru GQ (d + t) vs RSA (bytes)
        int gqSize = (gqSig.d.bitLength() + gqSig.t.bitLength()) / 8;
        System.out.println("GQ Size: ~" + gqSize + " bytes (Doar Appendix-ul)");
        System.out.println("RSA Size: " + rsaSig.length + " bytes");
    }
}