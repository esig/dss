package eu.europa.esig.dss.validation.process.qmatrix.qualification.checks.type.cert;

import eu.europa.esig.dss.validation.process.CertificatePolicyIdentifiers;
import eu.europa.esig.dss.validation.process.QCStatementPolicyIdentifiers;
import eu.europa.esig.dss.validation.process.qmatrix.qualification.checks.type.Type;
import eu.europa.esig.dss.validation.process.qmatrix.qualification.checks.type.TypeStrategy;
import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;

public class TypeByCertificatePreEIDAS implements TypeStrategy {

	private final CertificateWrapper signingCertificate;

	public TypeByCertificatePreEIDAS(CertificateWrapper signingCertificate) {
		this.signingCertificate = signingCertificate;
	}

	@Override
	public Type getType() {
		if (QCStatementPolicyIdentifiers.isQCCompliant(signingCertificate) || CertificatePolicyIdentifiers.isQCP(signingCertificate)
				|| CertificatePolicyIdentifiers.isQCPPlus(signingCertificate)) {
			return Type.ESIGN; // if QC -> ESign
		} else {
			return Type.UNKNOWN;
		}
	}

}
