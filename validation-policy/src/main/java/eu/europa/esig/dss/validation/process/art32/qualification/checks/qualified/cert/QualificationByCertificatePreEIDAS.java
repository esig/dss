package eu.europa.esig.dss.validation.process.art32.qualification.checks.qualified.cert;

import eu.europa.esig.dss.validation.policy.CertificatePolicyIdentifiers;
import eu.europa.esig.dss.validation.policy.QCStatementPolicyIdentifiers;
import eu.europa.esig.dss.validation.process.art32.qualification.checks.qualified.AbstractQualificationCondition;
import eu.europa.esig.dss.validation.process.art32.qualification.checks.qualified.QualifiedStatus;
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
			return QualifiedStatus.QC_FOR_ESIGN;
		} else {
			return QualifiedStatus.NOT_QC;
		}
	}

}
