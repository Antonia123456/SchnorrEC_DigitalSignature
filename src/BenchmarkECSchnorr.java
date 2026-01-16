public class BenchmarkECSchnorr {

    public static void runBenchmark(int iterations) throws Exception {

        ECSchnorr schnorr = new ECSchnorr();
        ECKeyPair keyPair = new ECKeyPair(schnorr.getParams());

        byte[] message = "Benchmark EC-Schnorr".getBytes();

        long signTime = 0;
        long verifyTime = 0;

        SignatureData sig = null;

        // Benchmark semnare
        for (int i = 0; i < iterations; i++) {
            long start = System.nanoTime();
            sig = schnorr.sign(message, keyPair);
            long end = System.nanoTime();
            signTime += (end - start);
        }

        // Benchmark verificare
        for (int i = 0; i < iterations; i++) {
            long start = System.nanoTime();
            schnorr.verify(message, sig, keyPair.publicKey);
            long end = System.nanoTime();
            verifyTime += (end - start);
        }

        System.out.println("=== EC-Schnorr Benchmark ===");
        System.out.println("Iteratii: " + iterations);
        System.out.println("Timp mediu semnare (ms): " + (signTime / iterations) / 1_000_000.0);
        System.out.println("Timp mediu verificare (ms): " + (verifyTime / iterations) / 1_000_000.0);
    }
}
