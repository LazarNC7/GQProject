import java.security.*;
import java.util.Base64;

public class RSABenchmark {
    private KeyPair pair;
    private Signature signEngine;

    public void setup(int keySize) throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(keySize);
        this.pair = keyGen.generateKeyPair();
        this.signEngine = Signature.getInstance("SHA256withRSA");
    }

    public byte[] sign(byte[] data) throws Exception {
        signEngine.initSign(pair.getPrivate());
        signEngine.update(data);
        return signEngine.sign();
    }

    public boolean verify(byte[] data, byte[] signature) throws Exception {
        signEngine.initVerify(pair.getPublic());
        signEngine.update(data);
        return signEngine.verify(signature);
    }
}