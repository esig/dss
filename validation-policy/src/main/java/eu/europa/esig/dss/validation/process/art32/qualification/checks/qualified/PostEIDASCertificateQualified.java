package eu.europa.esig.dss.validation.process.art32.qualification.checks.qualified;

import eu.europa.esig.dss.validation.policy.QCStatementPolicyIdentifiers;
import eu.europa.esig.dss.validation.process.art32.qualification.checks.CertificateCondition;
import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;

public class PostEIDASCertificateQualified implements CertificateCondition {

	@Override
	public boolean check(CertificateWrapper certificate) {
		return QCStatementPolicyIdentifiers.isQCCompliant(certificate); // TODO + QCType?
	}

}
