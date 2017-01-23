package eu.europa.esig.dss.validation.process.qmatrix.qualification.checks.type.cert;

import eu.europa.esig.dss.validation.process.QCStatementPolicyIdentifiers;
import eu.europa.esig.dss.validation.process.qmatrix.qualification.checks.QCTypeIdentifiers;
import eu.europa.esig.dss.validation.process.qmatrix.qualification.checks.type.Type;
import eu.europa.esig.dss.validation.process.qmatrix.qualification.checks.type.TypeStrategy;
import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;

public class TypeByCertificatePostEIDAS implements TypeStrategy {

	private final CertificateWrapper signingCertificate;

	public TypeByCertificatePostEIDAS(CertificateWrapper signingCertificate) {
		this.signingCertificate = signingCertificate;
	}

	@Override
	public Type getType() {
		boolean qcCompliant = QCStatementPolicyIdentifiers.isQCCompliant(signingCertificate);
		boolean esign = QCTypeIdentifiers.isQCTypeEsign(signingCertificate);
		boolean eseal = QCTypeIdentifiers.isQCTypeEseal(signingCertificate);
		boolean web = QCTypeIdentifiers.isQCTypeWeb(signingCertificate);

		boolean noneType = !(esign || eseal || web);

		if (qcCompliant && (noneType || esign)) {
			return Type.ESIGN;
		} else if (qcCompliant && (eseal || web)) {
			return Type.ESEAL;
		} else {
			return Type.UNKNOWN;
		}

	}

}
