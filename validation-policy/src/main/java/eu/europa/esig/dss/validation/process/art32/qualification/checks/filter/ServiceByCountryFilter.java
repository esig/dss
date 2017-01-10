package eu.europa.esig.dss.validation.process.art32.qualification.checks.filter;

import java.util.ArrayList;
import java.util.List;

import eu.europa.esig.dss.jaxb.diagnostic.XmlTrustedServiceProvider;
import eu.europa.esig.dss.utils.Utils;

/**
 * This class is used to filter trusted services by country code.
 * 
 * That's possible to find trusted certificates in more than one TL (eg : UK + PT)
 *
 */
public class ServiceByCountryFilter implements TrustedServiceFilter {

	private final String countryCode;

	public ServiceByCountryFilter(String countryCode) {
		this.countryCode = countryCode;
	}

	@Override
	public List<XmlTrustedServiceProvider> filter(List<XmlTrustedServiceProvider> tsps) {
		List<XmlTrustedServiceProvider> result = new ArrayList<XmlTrustedServiceProvider>();
		for (XmlTrustedServiceProvider tsp : tsps) {
			if (Utils.areStringsEqualIgnoreCase(countryCode, tsp.getCountryCode())) {
				result.add(tsp);
			}
		}
		return result;
	}

}
