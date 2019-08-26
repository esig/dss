package eu.europa.esig.dss.jaxb.parsers;

import eu.europa.esig.dss.enumerations.RevocationRefOrigin;

public class RevocationRefOriginParser {

	private RevocationRefOriginParser() {
	}

	public static RevocationRefOrigin parse(String v) {
		return RevocationRefOrigin.valueOf(v);
	}

	public static String print(RevocationRefOrigin v) {
		return v.name();
	}

}
