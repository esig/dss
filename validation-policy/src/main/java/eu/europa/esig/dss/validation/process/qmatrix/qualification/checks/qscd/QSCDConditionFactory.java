package eu.europa.esig.dss.validation.process.qmatrix.qualification.checks.qscd;

import java.util.List;

import eu.europa.esig.dss.validation.process.qmatrix.EIDASUtils;
import eu.europa.esig.dss.validation.process.qmatrix.qualification.checks.qscd.cert.QSCDByCertificatePostEIDAS;
import eu.europa.esig.dss.validation.process.qmatrix.qualification.checks.qscd.cert.QSCDByCertificatePreEIDAS;
import eu.europa.esig.dss.validation.process.qmatrix.qualification.checks.qscd.tl.QSCDByTL;
import eu.europa.esig.dss.validation.process.qmatrix.qualification.checks.qualified.QualifiedStatus;
import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;
import eu.europa.esig.dss.validation.reports.wrapper.TrustedServiceWrapper;

public final class QSCDConditionFactory {

	private QSCDConditionFactory() {
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
