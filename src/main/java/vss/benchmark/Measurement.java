package vss.benchmark;

public class Measurement {
	private long totalTime;
	private final int nTests;
	private long start;
	private long end;
	
	public Measurement(int nTests) {
		this.nTests = nTests;
	}
	
	public void reset() {
		totalTime = 0;
		start = 0;
		end = 0;
	}
	
	public double getAverageInMillis(int nDecimals) {
		double temp = Math.pow(10, nDecimals);
		return (int)(Math.round(((double) totalTime / nTests / 1_000_000.0) * temp)) / temp;
	}

	public long getTotalTime() {
		return totalTime;
	}

	public void start() {
		start = System.nanoTime();
	}
	
	public void stop() {
		end = System.nanoTime();
		totalTime += end - start;
	}

	@Override
	public String toString() {
		return "Measurement [totalTime=" + totalTime + ", nTests=" + nTests + ", start=" + start + ", end=" + end
				+ ", delta=" + (end - start) + "]";
	}
}
