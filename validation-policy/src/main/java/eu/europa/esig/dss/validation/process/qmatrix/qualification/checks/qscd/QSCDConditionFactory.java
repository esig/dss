package eu.europa.esig.dss.validation.process.qmatrix.qualification.checks.qscd;

import eu.europa.esig.dss.validation.process.Condition;
import eu.europa.esig.dss.validation.process.qmatrix.EIDASUtils;
import eu.europa.esig.dss.validation.process.qmatrix.qualification.checks.qscd.cert.QSCDByCertificatePostEIDAS;
import eu.europa.esig.dss.validation.process.qmatrix.qualification.checks.qscd.cert.QSCDByCertificatePreEIDAS;
import eu.europa.esig.dss.validation.process.qmatrix.qualification.checks.qscd.tl.QSCDByTL;
import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;
import eu.europa.esig.dss.validation.reports.wrapper.TrustedServiceWrapper;

public final class QSCDConditionFactory {

	private QSCDConditionFactory() {
	}

	public static Condition createQSCDFromCert(CertificateWrapper signingCertificate) {
		if (EIDASUtils.isPostEIDAS(signingCertificate.getNotBefore())) {
			return new QSCDByCertificatePostEIDAS(signingCertificate);
		} else {
			return new QSCDByCertificatePreEIDAS(signingCertificate);
		}
	}

	public static Condition createQSCDFromTL(TrustedServiceWrapper trustedService, Condition qualified, Condition qscdFromCertificate) {
		return new QSCDByTL(trustedService, qualified, qscdFromCertificate);
	}

}
