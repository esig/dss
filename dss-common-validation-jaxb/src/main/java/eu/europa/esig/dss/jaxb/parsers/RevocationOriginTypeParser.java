package eu.europa.esig.dss.jaxb.parsers;

import eu.europa.esig.dss.validation.RevocationOriginType;

public class RevocationOriginTypeParser {

	private RevocationOriginTypeParser() {
	}

	public static RevocationOriginType parse(String v) {
		return RevocationOriginType.valueOf(v);
	}

	public static String print(RevocationOriginType v) {
		return v.name();
	}

}
