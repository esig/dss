package eu.europa.esig.dss.jaxb.parsers;

import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;

public final class EncryptionAlgorithmParser {

	private EncryptionAlgorithmParser() {
	}

	public static EncryptionAlgorithm parse(String v) {
		if (v != null) {
			return EncryptionAlgorithm.forName(v);
		}
		return null;
	}

	public static String print(EncryptionAlgorithm v) {
		if (v != null) {
			return v.getName();
		}
		return null;
	}

}
