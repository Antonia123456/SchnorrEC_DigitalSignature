import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;

public class BenchmarkRSA {

    public static void runBenchmark(int iterations) throws Exception {

        // Generare chei RSA 3072
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(3072);
        KeyPair keyPair = kpg.generateKeyPair();

        Signature rsaSign = Signature.getInstance("SHA256withRSA");

        byte[] message = "Benchmark RSA".getBytes();
        byte[] signature = null;

        long signTime = 0;
        long verifyTime = 0;

        // Semnare
        for (int i = 0; i < iterations; i++) {
            rsaSign.initSign(keyPair.getPrivate());
            rsaSign.update(message);

            long start = System.nanoTime();
            signature = rsaSign.sign();
            long end = System.nanoTime();

            signTime += (end - start);
        }

        // Verificare
        for (int i = 0; i < iterations; i++) {
            rsaSign.initVerify(keyPair.getPublic());
            rsaSign.update(message);

            long start = System.nanoTime();
            rsaSign.verify(signature);
            long end = System.nanoTime();

            verifyTime += (end - start);
        }

        System.out.println("=== RSA-3072 Benchmark ===");
        System.out.println("Iteratii: " + iterations);
        System.out.println("Timp mediu semnare (ms): " + (signTime / iterations) / 1_000_000.0);
        System.out.println("Timp mediu verificare (ms): " + (verifyTime / iterations) / 1_000_000.0);
    }
}
