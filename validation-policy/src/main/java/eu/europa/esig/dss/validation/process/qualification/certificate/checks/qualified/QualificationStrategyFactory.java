package eu.europa.esig.dss.validation.process.qualification.certificate.checks.qualified;

import eu.europa.esig.dss.validation.process.qualification.EIDASUtils;
import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;
import eu.europa.esig.dss.validation.reports.wrapper.TrustedServiceWrapper;

public final class QualificationStrategyFactory {

	private QualificationStrategyFactory() {
	}

	public static QualificationStrategy createQualificationFromCert(CertificateWrapper signingCertificate) {
		if (EIDASUtils.isPostEIDAS(signingCertificate.getNotBefore())) {
			return new QualificationByCertificatePostEIDAS(signingCertificate);
		} else {
			return new QualificationByCertificatePreEIDAS(signingCertificate);
		}
	}

	public static QualificationStrategy createQualificationFromTL(TrustedServiceWrapper trustedService, QualificationStrategy qualifiedInCert) {
		return new QualificationByTL(trustedService, qualifiedInCert);
	}

	public static QualificationStrategy createQualificationFromCertAndTL(CertificateWrapper signingCertificate, TrustedServiceWrapper caQcTrustedService) {
		QualificationStrategy qcFromCert = createQualificationFromCert(signingCertificate);
		return createQualificationFromTL(caQcTrustedService, qcFromCert);
	}

}
