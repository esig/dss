package eu.europa.esig.dss.validation.process.art32.qualification.checks.qualified;

import eu.europa.esig.dss.validation.policy.CertificatePolicyIdentifiers;
import eu.europa.esig.dss.validation.policy.QCStatementPolicyIdentifiers;
import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;

public class PreEIDASCertificateQualified implements CertificateQualification {

	@Override
	public QualifiedStatus getQualifiedStatus(CertificateWrapper certificate) {
		if (QCStatementPolicyIdentifiers.isQCCompliant(certificate) || CertificatePolicyIdentifiers.isQCP(certificate)
				|| CertificatePolicyIdentifiers.isQCPPlus(certificate)) {
			return QualifiedStatus.QC_FOR_ESIGN;
		} else {
			return QualifiedStatus.NOT_QC;
		}
	}

}
