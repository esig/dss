package eu.europa.esig.dss.validation.process.art32.qualification.checks.qualified.cert;

import eu.europa.esig.dss.validation.process.QCStatementPolicyIdentifiers;
import eu.europa.esig.dss.validation.process.art32.QCTypeIdentifiers;
import eu.europa.esig.dss.validation.process.art32.qualification.checks.qualified.AbstractQualificationCondition;
import eu.europa.esig.dss.validation.process.art32.qualification.checks.qualified.QualifiedStatus;
import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;

public class QualificationByCertificatePostEIDAS extends AbstractQualificationCondition {

	private final CertificateWrapper signingCertificate;

	public QualificationByCertificatePostEIDAS(CertificateWrapper signingCertificate) {
		this.signingCertificate = signingCertificate;
	}

	@Override
	public QualifiedStatus getQualifiedStatus() {
		boolean qcCompliant = QCStatementPolicyIdentifiers.isQCCompliant(signingCertificate);
		boolean esign = QCTypeIdentifiers.isQCTypeEsign(signingCertificate);
		boolean eseal = QCTypeIdentifiers.isQCTypeEseal(signingCertificate);
		boolean web = QCTypeIdentifiers.isQCTypeWeb(signingCertificate);

		boolean noneType = !(esign || eseal || web);

		if (qcCompliant && (noneType || esign)) {
			return QualifiedStatus.QC_FOR_ESIGN;
		} else if (qcCompliant && (eseal || web)) {
			return QualifiedStatus.QC_NOT_FOR_ESIGN;
		} else {
			return QualifiedStatus.NOT_QC;
		}
	}

}
