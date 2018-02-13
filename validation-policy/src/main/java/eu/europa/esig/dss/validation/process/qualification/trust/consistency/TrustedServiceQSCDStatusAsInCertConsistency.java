package eu.europa.esig.dss.validation.process.qualification.trust.consistency;

import java.util.List;

import eu.europa.esig.dss.validation.process.qualification.trust.ServiceQualification;
import eu.europa.esig.dss.validation.reports.wrapper.TrustedServiceWrapper;

/**
 * A Trusted Service can not have QSCDStatusAsInCert and QSCD qualifiers for the same certificate.
 * 
 */
class TrustedServiceQSCDStatusAsInCertConsistency implements TrustedServiceCondition {

	@Override
	public boolean isConsistent(TrustedServiceWrapper trustedService) {
		List<String> capturedQualifiers = trustedService.getCapturedQualifiers();

		boolean asInCert = ServiceQualification.isQcQSCDStatusAsInCert(capturedQualifiers);

		boolean qcsd = ServiceQualification.isQcWithQSCD(capturedQualifiers) || ServiceQualification.isQcQSCDManagedOnBehalf(capturedQualifiers);

		if (asInCert) {
			return !qcsd;
		}

		return true;
	}

}
