package vss.facade;

/**
 * @author robin
 */
public enum Mode {
	LARGE_SECRET, //secret encoded as number is larger than prime field
	SMALL_SECRET //secret encoded as number is smaller than prime field
}
