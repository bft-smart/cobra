package confidential.demo.map.client;

import java.util.List;

public class Client {
	public static void main(String[] args) {
		KVStore kv = null;
		try {
			kv = new KVStore(100);
			
			getAll(kv);
			
			String key = "name";
			String value = "Nobody";
			put(kv, key, value);

			get(kv, key);

			key = "surname";
			value = "Who";
			put(kv, key, value);
			get(kv, key);
			
			key = "surname";
			value = "Why";
			put(kv, key, value);
			
			getAll(kv);
			
			remove(kv, key);
			
			getAll(kv);
			
			
		} catch (Exception e) {
			e.printStackTrace();
		} finally {
			if (kv != null)
				kv.close();
		}
	}
	
	private static void getAll(KVStore kv) {
		System.out.println("------------------");
		System.out.println("Reading all values");
		List<String> all = kv.getAll();
		System.out.println("Returned values:");
		if (all == null) {
			System.out.println("  Something is wrong, because getAll returned null");
			return;
		}
		for (String s : all)
			System.out.println("---> " + s);
	}
	
	private static void remove(KVStore kv, String key) {
		System.out.println("------------------");
		System.out.println("Removing: key = " + key);
		String value = kv.remove(key);
		System.out.println("Remove returns: value = " + value);
	}

	private static void get(KVStore kv, String key) {
		System.out.println("------------------");
		System.out.println("Reading: key = " + key);
		String value = kv.get(key);
		System.out.println("Reading returns: value = " + value);
	}

	private static void put(KVStore kv, String key, String value) {
		System.out.println("------------------");
		System.out.println("Putting: key = " + key + " | value = " + value);
		String oldValue = kv.put(key, value);
		System.out.println("Returned old value = " + oldValue);
	}
}
