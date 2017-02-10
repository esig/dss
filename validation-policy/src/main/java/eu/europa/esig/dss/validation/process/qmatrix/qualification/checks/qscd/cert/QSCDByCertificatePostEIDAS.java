package eu.europa.esig.dss.validation.process.qmatrix.qualification.checks.qscd.cert;

import eu.europa.esig.dss.validation.process.QCStatementPolicyIdentifiers;
import eu.europa.esig.dss.validation.process.qmatrix.qualification.checks.qscd.AbstractQSCDCondition;
import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;

public class QSCDByCertificatePostEIDAS extends AbstractQSCDCondition {

	private final CertificateWrapper certificate;

	public QSCDByCertificatePostEIDAS(CertificateWrapper certificate) {
		this.certificate = certificate;
	}

	@Override
	public boolean check() {
		// checks only in QC statement extension
		return QCStatementPolicyIdentifiers.isSupportedByQSCD(certificate);
	}

}
