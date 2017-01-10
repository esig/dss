package eu.europa.esig.dss.validation.process.art32.qualification.checks.qualified.tl;

import eu.europa.esig.dss.validation.policy.QCStatementPolicyIdentifiers;
import eu.europa.esig.dss.validation.policy.QCTypeIdentifiers;
import eu.europa.esig.dss.validation.process.art32.qualification.checks.CertificateCondition;
import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;

public class CertificateWithQCTypeESignCondition implements CertificateCondition {

	@Override
	public boolean check(CertificateWrapper certificate) {

		// (SigCert includes QcCompliance+QcType1 xor QcCompliance only xor QcType1 only (otherwise no effect))

		boolean qcCompliant = QCStatementPolicyIdentifiers.isQCCompliant(certificate);
		boolean esign = QCTypeIdentifiers.isQCTypeEsign(certificate);
		boolean eseal = QCTypeIdentifiers.isQCTypeEseal(certificate);
		boolean web = QCTypeIdentifiers.isQCTypeWeb(certificate);

		boolean qcCompliantWithEsign = qcCompliant && esign;
		boolean qcCompliantOnly = qcCompliant && !(esign && eseal && web);
		boolean qcTypeEsignOnly = esign && !(qcCompliant && eseal && web);

		return qcCompliantWithEsign || qcCompliantOnly || qcTypeEsignOnly;
	}

}
