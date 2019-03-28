package eu.europa.esig.dss.jaxb.parsers;

import eu.europa.esig.dss.validation.RevocationRefLocation;

public class RevocationRefLocationParser {

	private RevocationRefLocationParser() {
	}

	public static RevocationRefLocation parse(String v) {
		return RevocationRefLocation.valueOf(v);
	}

	public static String print(RevocationRefLocation v) {
		return v.name();
	}

}
