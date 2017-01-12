package eu.europa.esig.dss.validation.process.art32.qualification.checks.sscd.cert;

import eu.europa.esig.dss.validation.policy.QCStatementPolicyIdentifiers;
import eu.europa.esig.dss.validation.process.art32.qualification.checks.sscd.AbstractSSCDCondition;
import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;

public class SSCDByCertificatePostEIDAS extends AbstractSSCDCondition {

	private final CertificateWrapper certificate;

	public SSCDByCertificatePostEIDAS(CertificateWrapper certificate) {
		this.certificate = certificate;
	}

	@Override
	public boolean check() {
		// checks only in QC statement extension
		return QCStatementPolicyIdentifiers.isSupportedByQSCD(certificate);
	}

}
