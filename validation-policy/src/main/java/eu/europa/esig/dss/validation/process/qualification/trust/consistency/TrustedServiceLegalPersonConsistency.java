package eu.europa.esig.dss.validation.process.qualification.trust.consistency;

import java.util.List;

import eu.europa.esig.dss.validation.process.qualification.trust.ServiceQualification;
import eu.europa.esig.dss.validation.reports.wrapper.TrustedServiceWrapper;

/**
 * A Trusted Service can not have QCForESig and QCForLegalPerson qualifiers for the same certificate.
 */
class TrustedServiceLegalPersonConsistency implements TrustedServiceCondition {

	@Override
	public boolean isConsistent(TrustedServiceWrapper trustedService) {

		List<String> capturedQualifiers = trustedService.getCapturedQualifiers();

		boolean qcForLegalPerson = ServiceQualification.isQcForLegalPerson(capturedQualifiers);
		boolean qcForEsig = ServiceQualification.isQcForEsig(capturedQualifiers);

		return (!(qcForLegalPerson && qcForEsig));
	}

}
