package eu.europa.esig.dss.jaxb.parsers;

import eu.europa.esig.dss.enumerations.TimestampType;

public class TimestampTypeParser {

	private TimestampTypeParser() {
	}

	public static TimestampType parse(String v) {
		return TimestampType.valueOf(v);
	}

	public static String print(TimestampType v) {
		if (v != null) {
			return v.name();
		} else {
			return null;
		}
	}

}
