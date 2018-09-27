package eu.europa.esig.dss.jaxb.parsers;

import eu.europa.esig.dss.validation.SignatureScopeType;

public final class SignatureScopeTypeParser {

	private SignatureScopeTypeParser() {
	}

	public static SignatureScopeType parse(String v) {
		if (v != null) {
			return SignatureScopeType.valueOf(v);
		}
		return null;
	}

	public static String print(SignatureScopeType v) {
		if (v != null) {
			return v.name();
		}
		return null;
	}

}
