package eu.europa.esig.dss.validation.process.qualification.certificate.checks.qscd;

import eu.europa.esig.dss.validation.process.QCStatementPolicyIdentifiers;
import eu.europa.esig.dss.validation.process.qualification.certificate.QSCDStatus;
import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;

class QSCDByCertificatePostEIDAS implements QSCDStrategy {

	private final CertificateWrapper certificate;

	public QSCDByCertificatePostEIDAS(CertificateWrapper certificate) {
		this.certificate = certificate;
	}

	@Override
	public QSCDStatus getQSCDStatus() {
		// checks only in QC statement extension
		if (QCStatementPolicyIdentifiers.isSupportedByQSCD(certificate)) {
			return QSCDStatus.QSCD;
		} else {
			return QSCDStatus.NOT_QSCD;
		}
	}

}
