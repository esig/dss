package eu.europa.esig.dss.validation.process.qualification.certificate.checks.qualified;

import eu.europa.esig.dss.validation.process.QCStatementPolicyIdentifiers;
import eu.europa.esig.dss.validation.process.qualification.certificate.QualifiedStatus;
import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;

class QualificationByCertificatePostEIDAS implements QualificationStrategy {

	private final CertificateWrapper signingCertificate;

	public QualificationByCertificatePostEIDAS(CertificateWrapper signingCertificate) {
		this.signingCertificate = signingCertificate;
	}

	@Override
	public QualifiedStatus getQualifiedStatus() {
		if (QCStatementPolicyIdentifiers.isQCCompliant(signingCertificate)) {
			return QualifiedStatus.QC;
		} else {
			return QualifiedStatus.NOT_QC;
		}
	}

}
