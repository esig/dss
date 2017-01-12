package eu.europa.esig.dss.validation.process.art32.qualification.checks.sscd.cert;

import eu.europa.esig.dss.validation.policy.CertificatePolicyIdentifiers;
import eu.europa.esig.dss.validation.policy.QCStatementPolicyIdentifiers;
import eu.europa.esig.dss.validation.process.art32.qualification.checks.sscd.AbstractSSCDCondition;
import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;

public class SSCDByCertificatePreEIDAS extends AbstractSSCDCondition {

	private final CertificateWrapper certificate;

	public SSCDByCertificatePreEIDAS(CertificateWrapper certificate) {
		this.certificate = certificate;
	}

	@Override
	public boolean check() {

		// checks in policy id extension
		boolean policyIdSupportedByQSCD = CertificatePolicyIdentifiers.isSupportedByQSCD(certificate);

		// checks in QC statement extension
		boolean qcStatementSupportedByQSCD = QCStatementPolicyIdentifiers.isSupportedByQSCD(certificate);

		return policyIdSupportedByQSCD || qcStatementSupportedByQSCD;
	}

}
