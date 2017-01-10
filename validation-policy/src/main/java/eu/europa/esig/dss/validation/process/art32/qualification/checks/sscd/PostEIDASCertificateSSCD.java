package eu.europa.esig.dss.validation.process.art32.qualification.checks.sscd;

import eu.europa.esig.dss.validation.policy.QCStatementPolicyIdentifiers;
import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;

public class PostEIDASCertificateSSCD implements CertificateCondition {

	@Override
	public boolean check(CertificateWrapper certificate) {
		// checks only in QC statement extension
		return QCStatementPolicyIdentifiers.isSupportedByQSCD(certificate);
	}

}
