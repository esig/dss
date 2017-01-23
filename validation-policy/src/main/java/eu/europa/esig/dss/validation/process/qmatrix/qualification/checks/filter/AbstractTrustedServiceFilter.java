package eu.europa.esig.dss.validation.process.qmatrix.qualification.checks.filter;

import java.util.ArrayList;
import java.util.List;

import eu.europa.esig.dss.validation.reports.wrapper.TrustedServiceWrapper;

public abstract class AbstractTrustedServiceFilter implements TrustedServiceFilter {

	@Override
	public List<TrustedServiceWrapper> filter(List<TrustedServiceWrapper> originServices) {
		List<TrustedServiceWrapper> result = new ArrayList<TrustedServiceWrapper>();
		for (TrustedServiceWrapper service : originServices) {
			if (isAcceptable(service)) {
				result.add(service);
			}
		}
		return result;
	}

	abstract boolean isAcceptable(TrustedServiceWrapper service);

}
