package eu.europa.esig.dss.jaxb.parsers;

import eu.europa.esig.dss.enumerations.CertificateOrigin;

public class CertificateOriginParser {

	private CertificateOriginParser() {
	}

	public static CertificateOrigin parse(String v) {
		return CertificateOrigin.valueOf(v);
	}

	public static String print(CertificateOrigin v) {
		return v.name();
	}

}
