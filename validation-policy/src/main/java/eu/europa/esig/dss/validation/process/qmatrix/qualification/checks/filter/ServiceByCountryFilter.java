package eu.europa.esig.dss.validation.process.qmatrix.qualification.checks.filter;

import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.reports.wrapper.TrustedServiceWrapper;

/**
 * This class is used to filter trusted services by country code.
 * 
 * That's possible to find trusted certificates in more than one TL (eg : UK + PT)
 *
 */
public class ServiceByCountryFilter extends AbstractTrustedServiceFilter {

	private final String countryCode;

	public ServiceByCountryFilter(String countryCode) {
		this.countryCode = countryCode;
	}

	@Override
	boolean isAcceptable(TrustedServiceWrapper service) {
		return Utils.areStringsEqualIgnoreCase(countryCode, service.getCountryCode());
	}

}
