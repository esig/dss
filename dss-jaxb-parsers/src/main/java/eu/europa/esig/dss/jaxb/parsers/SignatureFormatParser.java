package eu.europa.esig.dss.jaxb.parsers;

import eu.europa.esig.dss.enumerations.SignatureLevel;

public class SignatureFormatParser {

	private SignatureFormatParser() {
	}

	public static SignatureLevel parse(String v) {
		if (v != null) {
			return SignatureLevel.valueOf(v);
		}
		return null;
	}

	public static String print(SignatureLevel v) {
		if (v != null) {
			return v.name();
		}
		return null;
	}

}
