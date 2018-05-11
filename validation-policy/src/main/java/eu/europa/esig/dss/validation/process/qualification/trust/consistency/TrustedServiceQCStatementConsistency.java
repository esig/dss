package eu.europa.esig.dss.validation.process.qualification.trust.consistency;

import java.util.List;

import eu.europa.esig.dss.validation.process.qualification.trust.ServiceQualification;
import eu.europa.esig.dss.validation.reports.wrapper.TrustedServiceWrapper;

/**
 * A Trusted service can not have QCStatement and NotQualified qualifiers for the same certificate.
 */
class TrustedServiceQCStatementConsistency implements TrustedServiceCondition {

	@Override
	public boolean isConsistent(TrustedServiceWrapper trustedService) {
		List<String> capturedQualifiers = trustedService.getCapturedQualifiers();

		boolean qcStatement = ServiceQualification.isQcStatement(capturedQualifiers);
		boolean notQualified = ServiceQualification.isNotQualified(capturedQualifiers);

		if (qcStatement) {
			return !notQualified;
		}
		return true;
	}

}
