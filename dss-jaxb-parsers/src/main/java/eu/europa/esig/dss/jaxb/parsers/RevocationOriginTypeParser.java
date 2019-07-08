package eu.europa.esig.dss.jaxb.parsers;

import eu.europa.esig.dss.enumerations.RevocationOrigin;

public class RevocationOriginTypeParser {

	private RevocationOriginTypeParser() {
	}

	public static RevocationOrigin parse(String v) {
		return RevocationOrigin.valueOf(v);
	}

	public static String print(RevocationOrigin v) {
		return v.name();
	}

}
