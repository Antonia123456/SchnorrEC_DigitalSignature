import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * Test semnare și verificare EC-Schnorr
 */
public class Main {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static void main(String[] args) throws Exception {

        ECSchnorr schnorr = new ECSchnorr();

        // Generare chei
        ECKeyPair keyPair = new ECKeyPair(schnorr.getParams());

        String message = "Semnatura Schnorr pe curbe eliptice";
        byte[] msgBytes = message.getBytes();

        // Semnare
        SignatureData sig = schnorr.sign(msgBytes, keyPair);

        // Verificare
        boolean valid = schnorr.verify(msgBytes, sig, keyPair.publicKey);

        System.out.println("Semnatura valida: " + valid);
    }
}
