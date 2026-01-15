import java.math.BigInteger;
import org.bouncycastle.math.ec.ECPoint;

/**
 * Structură pentru semnătura Schnorr (R, s)
 */
public class SignatureData {
    public final ECPoint R;
    public final BigInteger s;

    public SignatureData(ECPoint R, BigInteger s) {
        this.R = R;
        this.s = s;
    }
}
