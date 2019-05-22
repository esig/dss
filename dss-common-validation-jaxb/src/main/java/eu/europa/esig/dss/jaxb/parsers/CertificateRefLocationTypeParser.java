package eu.europa.esig.dss.jaxb.parsers;

import eu.europa.esig.dss.validation.CertificateRefLocationType;

public class CertificateRefLocationTypeParser {

	private CertificateRefLocationTypeParser() {
	}

	public static CertificateRefLocationType parse(String v) {
		return CertificateRefLocationType.valueOf(v);
	}

	public static String print(CertificateRefLocationType v) {
		return v.name();
	}

}
