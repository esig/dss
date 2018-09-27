package eu.europa.esig.dss.validation.process.qualification.trust.filter;

import java.util.Collections;
import java.util.Set;

import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.reports.wrapper.TrustedServiceWrapper;

/**
 * This class is used to filter trusted services by country code(s).
 * 
 * That's possible to find trusted certificates in more than one TL (eg : UK +
 * PT)
 *
 */
public class ServiceByCountryFilter extends AbstractTrustedServiceFilter {

	private final Set<String> countryCodes;

	public ServiceByCountryFilter(String countryCode) {
		this(Collections.singleton(countryCode));
	}

	public ServiceByCountryFilter(Set<String> countryCodes) {
		this.countryCodes = countryCodes;
	}

	@Override
	boolean isAcceptable(TrustedServiceWrapper service) {
		for (String countryCode : countryCodes) {
			if (Utils.areStringsEqualIgnoreCase(countryCode, service.getCountryCode())) {
				return true;
			}
		}
		return false;
	}

}
