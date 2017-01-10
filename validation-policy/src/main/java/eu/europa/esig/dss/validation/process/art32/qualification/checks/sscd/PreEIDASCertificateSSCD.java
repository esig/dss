package eu.europa.esig.dss.validation.process.art32.qualification.checks.sscd;

import eu.europa.esig.dss.validation.policy.CertificatePolicyIdentifiers;
import eu.europa.esig.dss.validation.policy.QCStatementPolicyIdentifiers;
import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;

public class PreEIDASCertificateSSCD implements CertificateCondition {

	@Override
	public boolean check(CertificateWrapper certificate) {

		// checks in policy id extension
		boolean policyIdSupportedByQSCD = CertificatePolicyIdentifiers.isSupportedByQSCD(certificate);

		// checks in QC statement extension
		boolean qcStatementSupportedByQSCD = QCStatementPolicyIdentifiers.isSupportedByQSCD(certificate);

		return policyIdSupportedByQSCD || qcStatementSupportedByQSCD;
	}

}
