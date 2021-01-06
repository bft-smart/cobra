package confidential.benchmark;

import bftsmart.tom.ServiceProxy;
import confidential.demo.map.client.Operation;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.util.Arrays;
import java.util.Collection;
import java.util.LinkedList;
import java.util.Random;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

/**
 * @author Robin
 */
public class SmartKVStoreClient {
    private static int initialId;

    public static void main(String[] args) {
        if (args.length != 5) {
            System.out.println("USAGE: ... SmartKVStoreClient <initial client id> " +
                    "<num clients> <number of ops> <request size> <write?>");
            System.exit(-1);
        }

        initialId = Integer.parseInt(args[0]);
        int numClients = Integer.parseInt(args[1]);
        int numOperations = Integer.parseInt(args[2]);
        int requestSize = Integer.parseInt(args[3]);
        boolean write = Boolean.parseBoolean(args[4]);


        Client[] clients = new Client[numClients];
        Random random = new Random(1L);
        String key = "key";
        byte[] data = new byte[requestSize];
        random.nextBytes(data);
        byte[] writeRequest = serialize(Operation.PUT, key, data);
        byte[] readRequest = serialize(Operation.GET, key, null);

        for (int i = 0; i < numClients; i++) {
            clients[i] = new Client(initialId + i, writeRequest, readRequest,
                    numOperations, data, write);
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

    private static byte[] serialize(Operation op, String str, byte[] data) {
        try(ByteArrayOutputStream bos = new ByteArrayOutputStream();
            ObjectOutput out = new ObjectOutputStream(bos)) {
            out.write((byte)op.ordinal());
            if(str != null)
                out.writeUTF(str);
            if (data != null) {
                out.writeInt(data.length);
                out.write(data);
            }
            out.flush();
            bos.flush();
            return bos.toByteArray();
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
    }

    private static class Client extends Thread {
        private final int id;
        private final int numOperations;
        private final boolean write;
        private final ServiceProxy proxy;
        private int rampup = 1000;
        private final byte[] writeRequest;
        private final byte[] readRequest;
        private final byte[] data;

        Client(int id, byte[] writeRequest, byte[] readRequest, int numOperations,
               byte[] data, boolean write) {
            super("Client " + id);
            this.id = id;
            this.numOperations = numOperations;
            this.write = write;
            this.writeRequest = writeRequest;
            this.readRequest = readRequest;
            this.data = data;

            this.proxy = new ServiceProxy(id);
        }

        @Override
        public void run() {
            if (id == initialId)
                System.out.println("Warming up...");
            byte[] response;
            try {
                proxy.invokeOrdered(writeRequest, null, (byte) -1);
                for (int i = 0; i < 50; i++) {
                    if (write)
                        proxy.invokeOrdered(writeRequest, null, (byte) -1);
                    else {
                        response = proxy.invokeUnordered(readRequest, null, (byte) -1);
                        if (!Arrays.equals(response, data))
                            throw new RuntimeException("Wrong response");
                    }
                }
                //Storage st = new Storage(numOperations);
                long[] latencies = null;
                if (id == initialId) {
                    latencies = new long[numOperations];
                    System.out.println("Executing experiment for " + numOperations + " ops");
                }
                for (int i = 0; i < numOperations; i++) {
                    long t2;
                    long t1 = System.nanoTime();
                    if (write) {
                        proxy.invokeOrdered(writeRequest, null, (byte) -1);
                    } else {
                        proxy.invokeUnordered(readRequest, null, (byte) -1);
                    }
                    t2 = System.nanoTime();
                    long latency = t2 - t1;
                    //st.store(latency);
                    if (latencies != null) {
                        latencies[i] = latency;
                    }
                    try {
                        if (rampup > 0) {
                            Thread.sleep(rampup);
                            rampup -= 100;
                        }
                    } catch (InterruptedException e) {
                        e.printStackTrace();
                    }
                }

                if (latencies != null) {
                    StringBuilder sb = new StringBuilder();
                    for (long latency : latencies) {
                        sb.append(latency);
                        sb.append(" ");
                    }
                    System.out.println("M: " + sb.toString().trim());
                    //System.out.println("Average time for " + numOperations + " executions (-10%) = " + st.getAverage(true) / 1000 + " us ");
                    //System.out.println("Standard deviation for " + numOperations + " executions (-10%) = " + st.getDP(true) / 1000 + " us ");
                    //System.out.println("Average time for " + numOperations + " executions (all samples) = " + st.getAverage(false) / 1000 + " us ");
                    //System.out.println("Standard deviation for " + numOperations + " executions (all samples) = " + st.getDP(false) / 1000 + " us ");
                    //System.out.println("Maximum time for " + numOperations + " executions (all samples) = " + st.getMax(false) / 1000 + " us ");
                }

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
