import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.SecureRandom;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECPoint;

/**
 * Implementare semnătură digitală Schnorr pe curbe eliptice
 */
public class ECSchnorr {

    private final ECParameterSpec ecSpec;
    private final SecureRandom random = new SecureRandom();

    public ECSchnorr() {
        // curbă standard NIST P-256
        this.ecSpec = ECNamedCurveTable.getParameterSpec("secp256r1");
    }

    public ECParameterSpec getParams() {
        return ecSpec;
    }

    /**
     * Semnare mesaj
     */
    public SignatureData sign(byte[] message, ECKeyPair keyPair) throws Exception {

        BigInteger n = ecSpec.getN();

        // k aleator
        BigInteger k = new BigInteger(n.bitLength(), random).mod(n);

        // R = kG
        ECPoint R = ecSpec.getG().multiply(k).normalize();

        // e = H(R || m)
        BigInteger e = hash(R, message);

        // s = k + e*x mod n
        BigInteger s = k.add(e.multiply(keyPair.privateKey)).mod(n);

        return new SignatureData(R, s);
    }

    /**
     * Verificare semnătură
     */
    public boolean verify(byte[] message, SignatureData sig, ECPoint publicKey) throws Exception {

        // e = H(R || m)
        BigInteger e = hash(sig.R, message);

        // sG
        ECPoint left = ecSpec.getG().multiply(sig.s).normalize();

        // R + eP
        ECPoint right = sig.R.add(publicKey.multiply(e)).normalize();

        // sG = R + eP
        return left.equals(right);
    }

    /**
     * Hash SHA-256 aplicat pe (R || mesaj)
     */
    private BigInteger hash(ECPoint R, byte[] message) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");

        byte[] rBytes = R.getEncoded(false);
        digest.update(rBytes);
        digest.update(message);

        return new BigInteger(1, digest.digest()).mod(ecSpec.getN());
    }
}
