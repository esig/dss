package eu.europa.esig.dss.validation.process.qmatrix.qualification.checks.qscd.cert;

import eu.europa.esig.dss.validation.process.CertificatePolicyIdentifiers;
import eu.europa.esig.dss.validation.process.QCStatementPolicyIdentifiers;
import eu.europa.esig.dss.validation.process.qmatrix.qualification.checks.qscd.AbstractQSCDCondition;
import eu.europa.esig.dss.validation.process.qmatrix.qualification.checks.qscd.QSCDStatus;
import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;

public class QSCDByCertificatePreEIDAS extends AbstractQSCDCondition {

	private final CertificateWrapper certificate;

	public QSCDByCertificatePreEIDAS(CertificateWrapper certificate) {
		this.certificate = certificate;
	}

	@Override
	public QSCDStatus getQSCDStatus() {

		// checks in policy id extension
		boolean policyIdSupportedByQSCD = CertificatePolicyIdentifiers.isSupportedByQSCD(certificate);

		// checks in QC statement extension
		boolean qcStatementSupportedByQSCD = QCStatementPolicyIdentifiers.isSupportedByQSCD(certificate);

		if (policyIdSupportedByQSCD || qcStatementSupportedByQSCD) {
			return QSCDStatus.QSCD;
		} else {
			return QSCDStatus.NOT_QSCD;
		}
	}

}
