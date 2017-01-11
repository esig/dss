package eu.europa.esig.dss.validation.process.art32.qualification.checks.sscd.cert;

import eu.europa.esig.dss.validation.policy.CertificatePolicyIdentifiers;
import eu.europa.esig.dss.validation.policy.QCStatementPolicyIdentifiers;
import eu.europa.esig.dss.validation.process.art32.qualification.checks.CertificateCondition;
import eu.europa.esig.dss.validation.process.art32.qualification.checks.sscd.SSCDStatus;
import eu.europa.esig.dss.validation.process.art32.qualification.checks.sscd.SSCDStrategy;
import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;

public class SSCDByCertificatePreEIDAS implements SSCDStrategy, CertificateCondition {

	private final CertificateWrapper certificate;

	public SSCDByCertificatePreEIDAS(CertificateWrapper certificate) {
		this.certificate = certificate;
	}

	@Override
	public SSCDStatus getSSCDStatus() {
		return check() ? SSCDStatus.SSCD : SSCDStatus.NOT_SSCD;
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
