package vss.facade;

public class SecretSharingException extends Exception {
	private static final long serialVersionUID = 1L;

	public SecretSharingException(String msg) {
		super(msg);
	}

	public SecretSharingException(String msg, Throwable throwable) {
		super(msg, throwable);
	}
}
