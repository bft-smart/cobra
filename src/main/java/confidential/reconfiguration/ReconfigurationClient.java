package confidential.reconfiguration;

import bftsmart.reconfiguration.BatchReconfiguration;
import bftsmart.reconfiguration.ReconfigureReply;
import bftsmart.reconfiguration.views.View;
import com.google.gson.Gson;
import com.google.gson.stream.JsonReader;
import confidential.Metadata;

import java.io.FileNotFoundException;
import java.io.FileReader;

/**
 * @author robin
 */
public class ReconfigurationClient {
	public static void main(String[] args) {
		int id = Integer.parseInt(args[0]);
		String reconfigurationFile = args[1];

		BatchReconfiguration rec = new BatchReconfiguration(id, "", null);
		rec.connect();
		try {
			Gson gson = new Gson();
			JsonReader reader = new JsonReader(new FileReader(reconfigurationFile));
			ReconfigurationInfo rInfo = gson.fromJson(reader, ReconfigurationInfo.class);
			if (rInfo.add_servers != null)
				for (Server addServer : rInfo.add_servers) {
					rec.addServer(addServer.id, addServer.ip, addServer.port, addServer.portRR);
				}
			if (rInfo.remove_servers != null)
				for (int removeServer : rInfo.remove_servers) {
					rec.removeServer(removeServer);
				}
			if (rInfo.f > 0)
				rec.setF(rInfo.f);
			ReconfigureReply r = rec.execute((byte) Metadata.DOES_NOT_VERIFY.ordinal());
			View v = r.getView();
			System.out.println("New view: " + v);
            /*if (rInfo.add_servers != null) {//TODO remove
                for (Server addServer : rInfo.add_servers) {
                    try {
                        String srcFile = "C:\\Users\\robin\\Desktop\\cobra\\rep0\\config\\currentView";
                        String dstFolder = "C:\\Users\\robin\\Desktop\\cobra\\rep"+ addServer.id +"\\config";
                        String[] a = { "CMD", "/C", "COPY", "/Y", srcFile, dstFolder };
                        Process p = Runtime.getRuntime().exec(a);
                        p.waitFor();
                    } catch (IOException | InterruptedException e) {
                        e.printStackTrace();
                    }
                }
            }*/
		} catch (FileNotFoundException e) {
			throw new RuntimeException("Couldn't find the reconfiguration file " + reconfigurationFile, e);
		}finally {
			rec.close();
		}
	}

	private static class ReconfigurationInfo {
		private Server[] add_servers;
		private int[] remove_servers;
		private int f;

		public ReconfigurationInfo() {}

		public ReconfigurationInfo(Server[] add_servers, int[] remove_servers, int f) {
			this.add_servers = add_servers;
			this.remove_servers = remove_servers;
			this.f = f;
		}
	}

	private static class Server {
		private int id;
		private String ip;
		private int port;
		private int portRR;

		public Server() {}

		public Server(int id, String ip, int port, int portRR) {
			this.id = id;
			this.ip = ip;
			this.port = port;
			this.portRR = portRR;
		}
	}
}
