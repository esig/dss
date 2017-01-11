package eu.europa.esig.dss.validation.process.art32.qualification.checks.sscd.cert;

import eu.europa.esig.dss.validation.policy.QCStatementPolicyIdentifiers;
import eu.europa.esig.dss.validation.process.art32.qualification.checks.CertificateCondition;
import eu.europa.esig.dss.validation.process.art32.qualification.checks.sscd.SSCDStatus;
import eu.europa.esig.dss.validation.process.art32.qualification.checks.sscd.SSCDStrategy;
import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;

public class SSCDByCertificatePostEIDAS implements SSCDStrategy, CertificateCondition {

	private final CertificateWrapper certificate;

	public SSCDByCertificatePostEIDAS(CertificateWrapper certificate) {
		this.certificate = certificate;
	}

	@Override
	public SSCDStatus getSSCDStatus() {
		return check() ? SSCDStatus.SSCD : SSCDStatus.NOT_SSCD;
	}

	@Override
	public boolean check() {
		// checks only in QC statement extension
		return QCStatementPolicyIdentifiers.isSupportedByQSCD(certificate);
	}

}
