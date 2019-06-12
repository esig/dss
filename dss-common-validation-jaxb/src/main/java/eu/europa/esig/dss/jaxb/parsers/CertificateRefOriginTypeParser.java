package eu.europa.esig.dss.jaxb.parsers;

import eu.europa.esig.dss.validation.CertificateRefOriginType;

public class CertificateRefOriginTypeParser {

	private CertificateRefOriginTypeParser() {
	}

	public static CertificateRefOriginType parse(String v) {
		return CertificateRefOriginType.valueOf(v);
	}

	public static String print(CertificateRefOriginType v) {
		return v.name();
	}

}
