package eu.europa.esig.dss.jaxb.parsers;

import eu.europa.esig.dss.validation.TimestampedObjectType;

public class TimestampedObjectTypeParser {

	public static TimestampedObjectType parse(String v) {
		if (v != null) {
			return TimestampedObjectType.valueOf(v);
		}
		return null;
	}

	public static String print(TimestampedObjectType v) {
		if (v != null) {
			return v.name();
		}
		return null;
	}

}
