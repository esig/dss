package eu.europa.esig.dss.validation.process.qmatrix.qualification.checks.qualified.cert;

import eu.europa.esig.dss.validation.process.CertificatePolicyIdentifiers;
import eu.europa.esig.dss.validation.process.QCStatementPolicyIdentifiers;
import eu.europa.esig.dss.validation.process.qmatrix.qualification.checks.qualified.AbstractQualificationCondition;
import eu.europa.esig.dss.validation.process.qmatrix.qualification.checks.qualified.QualifiedStatus;
import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;

public class QualificationByCertificatePreEIDAS extends AbstractQualificationCondition {

	private final CertificateWrapper signingCertificate;

	public QualificationByCertificatePreEIDAS(CertificateWrapper signingCertificate) {
		this.signingCertificate = signingCertificate;
	}

	@Override
	public QualifiedStatus getQualifiedStatus() {
		if (QCStatementPolicyIdentifiers.isQCCompliant(signingCertificate) || CertificatePolicyIdentifiers.isQCP(signingCertificate)
				|| CertificatePolicyIdentifiers.isQCPPlus(signingCertificate)) {
			return QualifiedStatus.QC;
		} else {
			return QualifiedStatus.NOT_QC;
		}
	}

}
