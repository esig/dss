package eu.europa.esig.dss.jaxb.parsers;

import eu.europa.esig.dss.validation.XmlTimestampType;

public class TimestampTypeParser {

	private TimestampTypeParser() {
	}

	public static XmlTimestampType parse(String v) {
		return XmlTimestampType.valueOf(v);
	}

	public static String print(XmlTimestampType v) {
		if (v != null) {
			return v.name();
		} else {
			return null;
		}
	}

}
