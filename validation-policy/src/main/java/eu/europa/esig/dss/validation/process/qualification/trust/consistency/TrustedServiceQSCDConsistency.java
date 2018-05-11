package eu.europa.esig.dss.validation.process.qualification.trust.consistency;

import java.util.List;

import eu.europa.esig.dss.validation.process.qualification.trust.ServiceQualification;
import eu.europa.esig.dss.validation.reports.wrapper.TrustedServiceWrapper;

/**
 * A Trusted Service can not have QSCD and NoQSCD qualifiers for the same certificate.
 * 
 */
class TrustedServiceQSCDConsistency implements TrustedServiceCondition {

	@Override
	public boolean isConsistent(TrustedServiceWrapper trustedService) {
		List<String> capturedQualifiers = trustedService.getCapturedQualifiers();

		boolean qscd = ServiceQualification.isQcWithQSCD(capturedQualifiers) || ServiceQualification.isQcQSCDStatusAsInCert(capturedQualifiers)
				|| ServiceQualification.isQcQSCDManagedOnBehalf(capturedQualifiers);

		boolean noQscd = ServiceQualification.isQcNoQSCD(capturedQualifiers);

		if (qscd) {
			return !noQscd;
		}

		return true;
	}

}
