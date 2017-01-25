package eu.europa.esig.dss.validation.process.qmatrix.qualification.checks.consistency;

import eu.europa.esig.dss.validation.reports.wrapper.TrustedServiceWrapper;

public interface TrustedServiceCondition {

	boolean isConsistent(TrustedServiceWrapper trustedService);

}
