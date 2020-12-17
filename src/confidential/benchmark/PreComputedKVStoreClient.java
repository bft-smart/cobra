package confidential.benchmark;

import bftsmart.tom.util.Storage;
import confidential.client.Response;
import vss.facade.SecretSharingException;

import java.util.Arrays;
import java.util.Collection;
import java.util.LinkedList;
import java.util.Random;
import java.util.concurrent.*;

/**
 * @author Robin
 */
public class PreComputedKVStoreClient {
    private static int initialId;

    public static void main(String[] args) throws SecretSharingException {
        if (args.length != 6) {
            System.out.println("USAGE: ... PreComputedKVStoreClient <initial client id> " +
                    "<num clients> <number of ops> <request size> <write?> <precomputed?>");
            System.exit(-1);
        }

        initialId = Integer.parseInt(args[0]);
        int numClients = Integer.parseInt(args[1]);
        int numOperations = Integer.parseInt(args[2]);
        int requestSize = Integer.parseInt(args[3]);
        boolean write = Boolean.parseBoolean(args[4]);
        boolean precomputed = Boolean.parseBoolean(args[5]);


        Client[] clients = new Client[numClients];

        for (int i = 0; i < numClients; i++) {
            clients[i] = new Client(initialId + i, precomputed, numOperations, requestSize, write);
        }

        ExecutorService executorService = Executors.newFixedThreadPool(numClients);
        Collection<Future<?>> tasks = new LinkedList<>();
        Random rndGenerator = new Random();
        for (Client client : clients) {
            try {
                Thread.sleep(rndGenerator.nextInt(50));
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
            tasks.add(executorService.submit(client));
        }
        Runtime.getRuntime().addShutdownHook(new Thread(executorService::shutdownNow));

        for (Future<?> task : tasks) {
            try {
                task.get();
            } catch (InterruptedException | ExecutionException e) {
                e.printStackTrace();
                executorService.shutdownNow();
                System.exit(-1);
            }
        }

        executorService.shutdown();
    }

    private static class Client extends Thread {
        private int id;
        private int numOperations;
        private boolean write;
        private PreComputedProxy proxy;
        private boolean preComputed;
        private int rampup = 1000;

        Client(int id, boolean precomputed, int numOperations, int requestSize, boolean write) throws SecretSharingException {
            super("Client " + id);
            this.id = id;
            this.numOperations = numOperations;
            this.write = write;
            this.preComputed = precomputed;
            this.proxy = new PreComputedProxy(id, requestSize, precomputed);
        }

        @Override
        public void run() {
            if (id == initialId)
                System.out.println("Warming up...");
            byte[] plainWriteData = proxy.plainWriteData;
            byte[] plainReadData = proxy.plainReadData;
            byte[] data = proxy.data;
            try {
                proxy.invokeOrdered(plainWriteData, data);
                Response response;
                for (int i = 0; i < 100; i++) {
                    if (write)
                        proxy.invokeOrdered(plainWriteData, data);
                    else {
                        response = proxy.invokeUnordered(plainReadData);
                        if (!preComputed && !Arrays.equals(response.getConfidentialData()[0], data))
                            throw new RuntimeException("Wrong response");
                    }
                }
                Storage st = new Storage(numOperations);

                if (id == initialId)
                    System.out.println("Executing experiment for " + numOperations + " ops");
                for (int i = 0; i < numOperations; i++) {
                    long t1 = System.nanoTime();
                    long t2;
                    if (write) {
                        proxy.invokeOrdered(plainWriteData, data);
                        t2 = System.nanoTime();
                    } else {
                        response = proxy.invokeUnordered(plainReadData);
                        t2 = System.nanoTime();
                        if (!preComputed && !Arrays.equals(response.getConfidentialData()[0], data)) {
                            System.out.println("Checking");
                            throw new RuntimeException("Wrong response");
                        }
                    }
                    long latency = t2 - t1;
                    st.store(latency);
                    try {
                        if (rampup > 0) {
                            Thread.sleep(rampup);
                            rampup -= 100;
                        }
                    } catch (InterruptedException e) {
                        e.printStackTrace();
                    }
                }

                if (id == initialId) {
                    System.out.println("Average time for " + numOperations + " executions (-10%) = " + st.getAverage(true) / 1000 + " us ");
                    System.out.println("Standard deviation for " + numOperations + " executions (-10%) = " + st.getDP(true) / 1000 + " us ");
                    System.out.println("Average time for " + numOperations + " executions (all samples) = " + st.getAverage(false) / 1000 + " us ");
                    System.out.println("Standard deviation for " + numOperations + " executions (all samples) = " + st.getDP(false) / 1000 + " us ");
                    System.out.println("Maximum time for " + numOperations + " executions (all samples) = " + st.getMax(false) / 1000 + " us ");
                }

            } catch (SecretSharingException e) {
                e.printStackTrace();
            } finally {
                proxy.close();
            }
        }

        @Override
        public void interrupt() {
            proxy.close();
            super.interrupt();
        }
    }
}
