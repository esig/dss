package eu.europa.esig.dss.jaxb.parsers;

import eu.europa.esig.dss.enumerations.CertificateRefOrigin;

public class CertificateRefOriginParser {

	private CertificateRefOriginParser() {
	}

	public static CertificateRefOrigin parse(String v) {
		return CertificateRefOrigin.valueOf(v);
	}

	public static String print(CertificateRefOrigin v) {
		return v.name();
	}

}
