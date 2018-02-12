package eu.europa.esig.dss.validation.process.qualification.certificate.checks.qscd;

import eu.europa.esig.dss.validation.process.qualification.EIDASUtils;
import eu.europa.esig.dss.validation.process.qualification.certificate.QualifiedStatus;
import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;
import eu.europa.esig.dss.validation.reports.wrapper.TrustedServiceWrapper;

public final class QSCDStrategyFactory {

	private QSCDStrategyFactory() {
	}

	public static QSCDStrategy createQSCDFromCert(CertificateWrapper signingCertificate) {
		if (EIDASUtils.isPostEIDAS(signingCertificate.getNotBefore())) {
			return new QSCDByCertificatePostEIDAS(signingCertificate);
		} else {
			return new QSCDByCertificatePreEIDAS(signingCertificate);
		}
	}

	public static QSCDStrategy createQSCDFromTL(TrustedServiceWrapper trustedService, QualifiedStatus qualified, QSCDStrategy qscdFromCertificate) {
		return new QSCDByTL(trustedService, qualified, qscdFromCertificate);
	}

	public static QSCDStrategy createQSCDFromCertAndTL(CertificateWrapper signingCertificate, TrustedServiceWrapper caQcTrustedService,
			QualifiedStatus qualified) {
		QSCDStrategy qscdFromCert = createQSCDFromCert(signingCertificate);
		return createQSCDFromTL(caQcTrustedService, qualified, qscdFromCert);
	}

}
