package eu.europa.esig.dss.jaxb.parsers;

import eu.europa.esig.dss.validation.DigestMatcherType;

public class DigestMatcherTypeParser {

	public static DigestMatcherType parse(String v) {
		if (v != null) {
			return DigestMatcherType.valueOf(v);
		}
		return null;
	}

	public static String print(DigestMatcherType v) {
		if (v != null) {
			return v.name();
		}
		return null;
	}

}
