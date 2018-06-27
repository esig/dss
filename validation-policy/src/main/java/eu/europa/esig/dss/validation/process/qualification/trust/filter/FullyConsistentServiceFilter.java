package eu.europa.esig.dss.validation.process.qualification.trust.filter;

import java.util.ArrayList;
import java.util.List;

import eu.europa.esig.dss.validation.process.qualification.trust.consistency.TrustedServiceChecker;
import eu.europa.esig.dss.validation.reports.wrapper.TrustedServiceWrapper;

public class FullyConsistentServiceFilter implements TrustedServiceFilter {

	@Override
	public List<TrustedServiceWrapper> filter(List<TrustedServiceWrapper> trustedServices) {
		List<TrustedServiceWrapper> result = new ArrayList<TrustedServiceWrapper>();
		for (TrustedServiceWrapper service : trustedServices) {
			if (TrustedServiceChecker.isFullyConsistent(service)) {
				result.add(service);
			}
		}
		return result;
	}

}
