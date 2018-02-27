package eu.europa.esig.dss.validation.process.qualification.certificate.checks.type;

import eu.europa.esig.dss.validation.process.QCStatementPolicyIdentifiers;
import eu.europa.esig.dss.validation.process.qualification.certificate.Type;
import eu.europa.esig.dss.validation.process.qualification.certificate.checks.QCTypeIdentifiers;
import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;

class TypeByCertificatePostEIDAS implements TypeStrategy {

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

		// multiple qcTypes are possible (mistake) but MUST be overruled by the trusted list
		boolean onlyOne = esign ^ eseal ^ web;

		if (qcCompliant && (noneType || (esign && onlyOne))) {
			return Type.ESIGN;
		} else if (qcCompliant && eseal && onlyOne) {
			return Type.ESEAL;
		} else if (qcCompliant && web && onlyOne) {
			return Type.WSA;
		} else {
			return Type.UNKNOWN;
		}

	}

}
