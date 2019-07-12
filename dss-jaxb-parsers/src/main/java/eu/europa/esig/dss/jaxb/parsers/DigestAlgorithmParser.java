package eu.europa.esig.dss.jaxb.parsers;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;

public final class DigestAlgorithmParser {

	private DigestAlgorithmParser() {
	}

	public static DigestAlgorithm parse(String v) {
		if (v != null) {
			return DigestAlgorithm.valueOf(v);
		}
		return null;
	}

	public static String print(DigestAlgorithm v) {
		if (v != null) {
			return v.name();
		}
		return null;
	}

}
