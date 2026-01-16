import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;

public class BenchmarkECDSA {

    public static void runBenchmark(int iterations) throws Exception {

        // Generator chei EC
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        keyGen.initialize(256);
        KeyPair keyPair = keyGen.generateKeyPair();

        Signature ecdsa = Signature.getInstance("SHA256withECDSA");

        byte[] message = "Benchmark ECDSA".getBytes();

        long signTime = 0;
        long verifyTime = 0;

        byte[] signature = null;

        // Semnare
        for (int i = 0; i < iterations; i++) {
            ecdsa.initSign(keyPair.getPrivate());
            ecdsa.update(message);

            long start = System.nanoTime();
            signature = ecdsa.sign();
            long end = System.nanoTime();

            signTime += (end - start);
        }

        // Verificare
        for (int i = 0; i < iterations; i++) {
            ecdsa.initVerify(keyPair.getPublic());
            ecdsa.update(message);

            long start = System.nanoTime();
            ecdsa.verify(signature);
            long end = System.nanoTime();

            verifyTime += (end - start);
        }

        System.out.println("=== ECDSA Benchmark ===");
        System.out.println("Iteratii: " + iterations);
        System.out.println("Timp mediu semnare (ms): " + (signTime / iterations) / 1_000_000.0);
        System.out.println("Timp mediu verificare (ms): " + (verifyTime / iterations) / 1_000_000.0);
    }
}
