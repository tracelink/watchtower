package com.tracelink.appsec.watchtower.core.benchmark;

/**
 * An interface for known, global timers
 * 
 * @author csmith
 *
 */
public interface TimerType {
	/**
	 * @return the "friendly" name for this timer
	 */
	String getExternalName();

	/**
	 * Default Timers for all scans
	 * 
	 * @author csmith
	 *
	 */
	enum DefaultTimerType implements TimerType {
		/**
		 * Total time from start to finish
		 */
		WALL_CLOCK("Total Time"),
		/**
		 * time spent scanning
		 */
		SCAN("Total Scan Time"),
		/**
		 * time spent making the report
		 */
		REPORT_GENERATE("Generate Report");

		private final String extName;

		DefaultTimerType(String externalName) {
			this.extName = externalName;
		}

		public String getExternalName() {
			return this.extName;
		}
	}
}
