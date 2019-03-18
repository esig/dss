package eu.europa.esig.dss.jaxb.parsers;

import eu.europa.esig.dss.validation.RevocationSourceType;

public class RevocationSourceTypeParser {

	private RevocationSourceTypeParser() {
	}

	public static RevocationSourceType parse(String v) {
		return RevocationSourceType.valueOf(v);
	}

	public static String print(RevocationSourceType v) {
		return v.name();
	}

}
