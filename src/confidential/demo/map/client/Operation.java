package confidential.demo.map.client;

public enum Operation {
	PUT, 
	GET, 
	GET_ALL, 
	REMOVE;

	public static Operation[] values = values();

	public static Operation getOperation(int ordinal) {
		return values[ordinal];
	}
}
