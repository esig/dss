package eu.europa.esig.dss.jaxb.parsers;

import eu.europa.esig.dss.enumerations.CertificateSourceType;

public class CertificateSourceTypeParser {

	private CertificateSourceTypeParser() {
	}

	public static CertificateSourceType parse(String v) {
		return CertificateSourceType.valueOf(v);
	}

	public static String print(CertificateSourceType v) {
		return v.name();
	}

}
