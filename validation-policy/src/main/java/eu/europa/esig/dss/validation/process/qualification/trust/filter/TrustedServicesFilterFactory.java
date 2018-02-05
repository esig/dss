package eu.europa.esig.dss.validation.process.qualification.trust.filter;

import java.util.Date;

public final class TrustedServicesFilterFactory {

	private TrustedServicesFilterFactory() {
	}

	public static TrustedServiceFilter createFilterByGranted() {
		return new GrantedServiceFilter();
	}

	public static TrustedServiceFilter createFilterByCaQc() {
		return new CaQcServiceFilter();
	}

	public static TrustedServiceFilter createFilterByDate(Date date) {
		return new ServiceByDateFilter(date);
	}

	public static TrustedServiceFilter createFilterByCountry(String countryCode) {
		return new ServiceByCountryFilter(countryCode);
	}

}
