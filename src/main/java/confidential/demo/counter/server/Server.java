package confidential.demo.counter.server;

public class Server {
    public static void main(String[] args) {
        new CounterServer(Integer.parseInt(args[0]));
    }
}
