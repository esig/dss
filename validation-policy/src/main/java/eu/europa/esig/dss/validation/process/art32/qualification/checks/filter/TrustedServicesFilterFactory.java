package eu.europa.esig.dss.validation.process.art32.qualification.checks.filter;

import java.util.Date;

public final class TrustedServicesFilterFactory {

	private TrustedServicesFilterFactory() {
	}

	public static TrustedServiceFilter createFilterForEsign() {
		return new ServiceForESignFilter();
	}

	public static TrustedServiceFilter createFilterByDate(Date date) {
		return new ServiceByDateFilter(date);
	}

	public static TrustedServiceFilter createFilterByCountry(String countryCode) {
		return new ServiceByCountryFilter(countryCode);
	}

}
