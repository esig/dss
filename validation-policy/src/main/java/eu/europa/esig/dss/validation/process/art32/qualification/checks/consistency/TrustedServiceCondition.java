package eu.europa.esig.dss.validation.process.art32.qualification.checks.consistency;

import eu.europa.esig.dss.validation.reports.wrapper.TrustedServiceWrapper;

public interface TrustedServiceCondition {

	boolean isConsistent(TrustedServiceWrapper trustedService);

}
