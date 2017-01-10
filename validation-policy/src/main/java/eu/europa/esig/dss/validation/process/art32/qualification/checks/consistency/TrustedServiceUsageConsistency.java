package eu.europa.esig.dss.validation.process.art32.qualification.checks.consistency;

import java.util.List;

import eu.europa.esig.dss.jaxb.diagnostic.XmlTrustedService;
import eu.europa.esig.dss.validation.policy.ServiceQualification;
import eu.europa.esig.dss.validation.process.art32.qualification.checks.TrustedServiceCondition;

/**
 * A Trusted Service can only have one of these values {QcForEsig, QcForEseal or QcForWSA} or none.
 * 
 */
public class TrustedServiceUsageConsistency implements TrustedServiceCondition {

	@Override
	public boolean isConsistent(XmlTrustedService trustedService) {

		List<String> capturedQualifiers = trustedService.getCapturedQualifiers();

		boolean qcForEsig = ServiceQualification.isQcForEsig(capturedQualifiers);
		boolean qcForEseal = ServiceQualification.isQcForEseal(capturedQualifiers);
		boolean qcForWSA = ServiceQualification.isQcForWSA(capturedQualifiers);

		boolean noneOfThem = !(qcForEsig || qcForEseal || qcForWSA);
		boolean onlyOneOfThem = qcForEsig ^ qcForEseal ^ qcForWSA; // ^ = XOR

		return noneOfThem || onlyOneOfThem;
	}

}
