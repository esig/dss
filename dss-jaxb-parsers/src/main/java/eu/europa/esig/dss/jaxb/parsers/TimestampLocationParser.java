package eu.europa.esig.dss.jaxb.parsers;

import eu.europa.esig.dss.enumerations.TimestampLocation;

public class TimestampLocationParser {

	private TimestampLocationParser() {
	}

	public static TimestampLocation parse(String v) {
		return TimestampLocation.valueOf(v);
	}

	public static String print(TimestampLocation v) {
		if (v != null) {
			return v.name();
		} else {
			return null;
		}
	}

}
