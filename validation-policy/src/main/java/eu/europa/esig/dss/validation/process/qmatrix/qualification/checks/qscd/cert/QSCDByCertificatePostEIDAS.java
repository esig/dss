package eu.europa.esig.dss.validation.process.qmatrix.qualification.checks.qscd.cert;

import eu.europa.esig.dss.validation.process.QCStatementPolicyIdentifiers;
import eu.europa.esig.dss.validation.process.qmatrix.qualification.checks.qscd.AbstractQSCDCondition;
import eu.europa.esig.dss.validation.process.qmatrix.qualification.checks.qscd.QSCDStatus;
import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;

public class QSCDByCertificatePostEIDAS extends AbstractQSCDCondition {

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
