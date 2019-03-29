package eu.europa.esig.dss.jaxb.parsers;

import eu.europa.esig.dss.validation.XmlCertificateSourceType;

public class CertificateSourceTypeParser {

	private CertificateSourceTypeParser() {
	}

	public static XmlCertificateSourceType parse(String v) {
		return XmlCertificateSourceType.valueOf(v);
	}

	public static String print(XmlCertificateSourceType v) {
		return v.name();
	}

}
