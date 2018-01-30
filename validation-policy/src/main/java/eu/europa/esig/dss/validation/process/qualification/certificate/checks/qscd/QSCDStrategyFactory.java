package eu.europa.esig.dss.validation.process.qualification.certificate.checks.qscd;

import java.util.List;

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

	public static QSCDStrategy createQSCDFromTL(List<TrustedServiceWrapper> trustedServices, QualifiedStatus qualified, QSCDStrategy qscdFromCertificate) {
		return new QSCDByTL(trustedServices, qualified, qscdFromCertificate);
	}

	public static QSCDStrategy createQSCDFromCertAndTL(CertificateWrapper signingCertificate, List<TrustedServiceWrapper> caQcTrustedServices,
			QualifiedStatus qualified) {
		QSCDStrategy qscdFromCert = createQSCDFromCert(signingCertificate);
		return createQSCDFromTL(caQcTrustedServices, qualified, qscdFromCert);
	}

}
