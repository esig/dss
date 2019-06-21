package eu.europa.esig.dss.jaxb.parsers;

import eu.europa.esig.dss.validation.CertificateOriginType;

public class CertificateOriginTypeParser {

	private CertificateOriginTypeParser() {
	}

	public static CertificateOriginType parse(String v) {
		return CertificateOriginType.valueOf(v);
	}

	public static String print(CertificateOriginType v) {
		return v.name();
	}

}
