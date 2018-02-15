package eu.europa.esig.dss.validation.process.qualification.certificate.checks.qscd;

import eu.europa.esig.dss.validation.process.CertificatePolicyIdentifiers;
import eu.europa.esig.dss.validation.process.QCStatementPolicyIdentifiers;
import eu.europa.esig.dss.validation.process.qualification.certificate.QSCDStatus;
import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;

class QSCDByCertificatePreEIDAS implements QSCDStrategy {

	private final CertificateWrapper certificate;

	public QSCDByCertificatePreEIDAS(CertificateWrapper certificate) {
		this.certificate = certificate;
	}

	@Override
	public QSCDStatus getQSCDStatus() {

		// checks in policy id extension
		boolean policyIdSupportedByQSCD = CertificatePolicyIdentifiers.isQCPPlus(certificate);

		// checks in QC statement extension
		boolean qcStatementSupportedByQSCD = QCStatementPolicyIdentifiers.isSupportedByQSCD(certificate);

		if (policyIdSupportedByQSCD || qcStatementSupportedByQSCD) {
			return QSCDStatus.QSCD;
		} else {
			return QSCDStatus.NOT_QSCD;
		}
	}

}
