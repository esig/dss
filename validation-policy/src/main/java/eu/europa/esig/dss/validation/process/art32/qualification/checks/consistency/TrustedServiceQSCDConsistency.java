package eu.europa.esig.dss.validation.process.art32.qualification.checks.consistency;

import java.util.List;

import eu.europa.esig.dss.jaxb.diagnostic.XmlTrustedService;
import eu.europa.esig.dss.validation.policy.ServiceQualification;

/**
 * A Trusted Service can not have SSCD and NoSSCD qualifiers for the same certificate.
 * 
 */
public class TrustedServiceQSCDConsistency implements TrustedServiceCondition {

	@Override
	public boolean isConsistent(XmlTrustedService trustedService) {
		List<String> capturedQualifiers = trustedService.getCapturedQualifiers();

		boolean sscd = ServiceQualification.isQcWithSSCD(capturedQualifiers) || ServiceQualification.isQcSscdStatusAsInCert(capturedQualifiers)
				|| ServiceQualification.isQcSscdManagedOnBehalf(capturedQualifiers);

		boolean noSscd = ServiceQualification.isQcNoSSCD(capturedQualifiers);

		if (sscd) {
			return !noSscd;
		}

		return true;
	}

}
