package eu.europa.esig.dss.validation.process.qmatrix.qualification.checks.filter;

import java.util.Date;

public final class TrustedServicesFilterFactory {

	private TrustedServicesFilterFactory() {
	}

	public static TrustedServiceFilter createFilterForAcceptableCAQC() {
		return new AcceptableCAQCServiceFilter();
	}

	public static TrustedServiceFilter createFilterByDate(Date date) {
		return new ServiceByDateFilter(date);
	}

	public static TrustedServiceFilter createFilterByCountry(String countryCode) {
		return new ServiceByCountryFilter(countryCode);
	}

}
