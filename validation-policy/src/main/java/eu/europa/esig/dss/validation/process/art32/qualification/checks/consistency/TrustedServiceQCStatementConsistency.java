package eu.europa.esig.dss.validation.process.art32.qualification.checks.consistency;

import java.util.List;

import eu.europa.esig.dss.jaxb.diagnostic.XmlTrustedService;
import eu.europa.esig.dss.validation.policy.ServiceQualification;

/**
 * A Trusted service can not have QCStatement and NotQualified qualifiers for the same certificate.
 */
public class TrustedServiceQCStatementConsistency implements TrustedServiceCondition {

	@Override
	public boolean isConsistent(XmlTrustedService trustedService) {
		List<String> capturedQualifiers = trustedService.getCapturedQualifiers();

		boolean qcStatement = ServiceQualification.isQcStatement(capturedQualifiers);
		boolean notQualified = ServiceQualification.isNotQualified(capturedQualifiers);

		if (qcStatement) {
			return !notQualified;
		}
		return true;
	}

}
