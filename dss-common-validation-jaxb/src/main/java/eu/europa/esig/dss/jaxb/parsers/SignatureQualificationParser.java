package eu.europa.esig.dss.jaxb.parsers;

import eu.europa.esig.dss.validation.SignatureQualification;

public class SignatureQualificationParser {

	public static SignatureQualification parse(String v) {
		return SignatureQualification.fromReadable(v);
	}

	public static String print(SignatureQualification v) {
		if (v != null) {
			return v.getReadable();
		}
		return null;
	}
}
