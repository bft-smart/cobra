package confidential.demo.statechecker;

public enum Operation {
	PUT, 
	GET;

	public static Operation[] values = values();

	public static Operation getOperation(int ordinal) {
		return values[ordinal];
	}
}
