package eu.europa.esig.dss.jaxb.parsers;

import eu.europa.esig.dss.validation.RevocationType;

public class RevocationTypeParser {

	private RevocationTypeParser() {
	}

	public static RevocationType parse(String v) {
		return RevocationType.valueOf(v);
	}

	public static String print(RevocationType v) {
		if (v != null) {
			return v.name();
		} else {
			return null;
		}
	}

}
