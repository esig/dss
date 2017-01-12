package eu.europa.esig.dss.validation.process.art32.qualification.checks.qualified;

import eu.europa.esig.dss.validation.process.art32.EIDASUtils;
import eu.europa.esig.dss.validation.process.art32.qualification.checks.qualified.cert.QualificationByCertificatePostEIDAS;
import eu.europa.esig.dss.validation.process.art32.qualification.checks.qualified.cert.QualificationByCertificatePreEIDAS;
import eu.europa.esig.dss.validation.process.art32.qualification.checks.qualified.tl.QualificationByTL;
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

	public static QualificationStrategy createQualificationFromTL(TrustedServiceWrapper trustedService, CertificateWrapper signingCertificate,
			QualificationStrategy qualifiedInCert) {
		return new QualificationByTL(trustedService, signingCertificate, qualifiedInCert);
	}

}
