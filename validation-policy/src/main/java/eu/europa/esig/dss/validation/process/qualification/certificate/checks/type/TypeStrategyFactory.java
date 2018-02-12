package eu.europa.esig.dss.validation.process.qualification.certificate.checks.type;

import eu.europa.esig.dss.validation.process.qualification.EIDASUtils;
import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;
import eu.europa.esig.dss.validation.reports.wrapper.TrustedServiceWrapper;

public final class TypeStrategyFactory {

	private TypeStrategyFactory() {
	}

	public static TypeStrategy createTypeFromCert(CertificateWrapper signingCertificate) {
		if (EIDASUtils.isPostEIDAS(signingCertificate.getNotBefore())) {
			return new TypeByCertificatePostEIDAS(signingCertificate);
		} else {
			return new TypeByCertificatePreEIDAS(signingCertificate);
		}
	}

	public static TypeStrategy createTypeFromTL(TrustedServiceWrapper trustedService, TypeStrategy typeInCert) {
		return new TypeByTL(trustedService, typeInCert);
	}

	public static TypeStrategy createTypeFromCertAndTL(CertificateWrapper signingCertificate, TrustedServiceWrapper caQcTrustedService) {
		TypeStrategy typeFromCert = createTypeFromCert(signingCertificate);
		return createTypeFromTL(caQcTrustedService, typeFromCert);
	}

}
