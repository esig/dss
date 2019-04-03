package eu.europa.esig.dss.jaxb.parsers;

import eu.europa.esig.dss.validation.XmlTimestampLocation;

public class TimestampLocationParser {

	private TimestampLocationParser() {
	}

	public static XmlTimestampLocation parse(String v) {
		return XmlTimestampLocation.valueOf(v);
	}

	public static String print(XmlTimestampLocation v) {
		if (v != null) {
			return v.name();
		} else {
			return null;
		}
	}

}
