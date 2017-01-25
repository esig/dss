package eu.europa.esig.dss.validation.process.qmatrix.qualification.checks.qualified.cert;

import eu.europa.esig.dss.validation.process.QCStatementPolicyIdentifiers;
import eu.europa.esig.dss.validation.process.qmatrix.qualification.checks.qualified.AbstractQualificationCondition;
import eu.europa.esig.dss.validation.process.qmatrix.qualification.checks.qualified.QualifiedStatus;
import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;

public class QualificationByCertificatePostEIDAS extends AbstractQualificationCondition {

	private final CertificateWrapper signingCertificate;

	public QualificationByCertificatePostEIDAS(CertificateWrapper signingCertificate) {
		this.signingCertificate = signingCertificate;
	}

	@Override
	public QualifiedStatus getQualifiedStatus() {
		boolean qcCompliant = QCStatementPolicyIdentifiers.isQCCompliant(signingCertificate);

		if (qcCompliant) {
			return QualifiedStatus.QC;
		} else {
			return QualifiedStatus.NOT_QC;
		}
	}

}
