import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECPoint;

/**
 * Generează perechea de chei EC pentru Schnorr
 */
public class ECKeyPair {

    public final BigInteger privateKey;
    public final ECPoint publicKey;

    public ECKeyPair(ECParameterSpec ecSpec) {
        SecureRandom random = new SecureRandom();
        BigInteger n = ecSpec.getN();

        // cheie privată d ∈ [1, n-1]
        this.privateKey = new BigInteger(n.bitLength(), random).mod(n);

        // cheie publică P = dG
        this.publicKey = ecSpec.getG().multiply(privateKey).normalize();
    }
}
