package eu.europa.esig.dss.validation.process.art32.qualification.checks.consistency;

import eu.europa.esig.dss.validation.reports.wrapper.TrustedServiceWrapper;

public final class TrustedServiceChecker {

	private TrustedServiceChecker() {
	}

	public static boolean isLegalPersonConsistent(TrustedServiceWrapper service) {
		TrustedServiceCondition condition = new TrustedServiceLegalPersonConsistency();
		return condition.isConsistent(service);
	}

	public static boolean isQCStatementConsistent(TrustedServiceWrapper service) {
		TrustedServiceCondition condition = new TrustedServiceQCStatementConsistency();
		return condition.isConsistent(service);
	}

	public static boolean isQSCDConsistent(TrustedServiceWrapper service) {
		TrustedServiceCondition condition = new TrustedServiceQSCDConsistency();
		return condition.isConsistent(service);
	}

	public static boolean isUsageConsistent(TrustedServiceWrapper service) {
		TrustedServiceCondition condition = new TrustedServiceUsageConsistency();
		return condition.isConsistent(service);
	}

}
