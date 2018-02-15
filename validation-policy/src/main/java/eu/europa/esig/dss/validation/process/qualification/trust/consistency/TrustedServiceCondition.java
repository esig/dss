package eu.europa.esig.dss.validation.process.qualification.trust.consistency;

import eu.europa.esig.dss.validation.reports.wrapper.TrustedServiceWrapper;

public interface TrustedServiceCondition {

	boolean isConsistent(TrustedServiceWrapper trustedService);

}
