package eu.europa.esig.dss.jaxb.parsers;

import eu.europa.esig.dss.validation.CertificateQualification;

public final class CertificateQualificationParser {

	private CertificateQualificationParser() {
	}

	public static CertificateQualification parse(String v) {
		return CertificateQualification.fromReadable(v);
	}

	public static String print(CertificateQualification v) {
		if (v != null) {
			return v.getReadable();
		}
		return null;
	}
}
