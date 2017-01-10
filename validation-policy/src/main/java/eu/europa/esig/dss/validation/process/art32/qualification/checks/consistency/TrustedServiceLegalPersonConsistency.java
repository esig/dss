package eu.europa.esig.dss.validation.process.art32.qualification.checks.consistency;

import java.util.List;

import eu.europa.esig.dss.jaxb.diagnostic.XmlTrustedService;
import eu.europa.esig.dss.validation.policy.ServiceQualification;

/**
 * A Trusted Service can not have QCForESig and QCForLegalPerson qualifiers for the same certificate.
 */
public class TrustedServiceLegalPersonConsistency implements TrustedServiceCondition {

	@Override
	public boolean isConsistent(XmlTrustedService trustedService) {

		List<String> capturedQualifiers = trustedService.getCapturedQualifiers();

		boolean qcForLegalPerson = ServiceQualification.isQcForLegalPerson(capturedQualifiers);
		boolean qcForEsig = ServiceQualification.isQcForEsig(capturedQualifiers);

		return (!(qcForLegalPerson && qcForEsig));
	}

}
