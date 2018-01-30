package eu.europa.esig.dss.validation.process.qualification.certificate.checks.type;

import java.util.List;

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

	public static TypeStrategy createTypeFromTL(List<TrustedServiceWrapper> trustedServices, TypeStrategy typeInCert) {
		return new TypeByTL(trustedServices, typeInCert);
	}

	public static TypeStrategy createTypeFromCertAndTL(CertificateWrapper signingCertificate, List<TrustedServiceWrapper> caQcTrustedServices) {
		TypeStrategy typeFromCert = createTypeFromCert(signingCertificate);
		return createTypeFromTL(caQcTrustedServices, typeFromCert);
	}

}
