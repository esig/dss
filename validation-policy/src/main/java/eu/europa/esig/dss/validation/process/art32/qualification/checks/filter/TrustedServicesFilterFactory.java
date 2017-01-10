package eu.europa.esig.dss.validation.process.art32.qualification.checks.filter;

import java.util.Date;

import eu.europa.esig.dss.validation.process.art32.EIDASConstants;

public final class TrustedServicesFilterFactory {

	private TrustedServicesFilterFactory() {
	}

	public static TrustedServiceFilter createFilterForEsign(Date date) {
		if (EIDASConstants.EIDAS_DATE.before(date)) {
			return new PreEIDASServiceForESignFilter();
		} else {
			return new PostEIDASServiceForESignFilter();
		}
	}

	public static TrustedServiceFilter createFilterByDate(Date date) {
		return new ServiceByDateFilter(date);
	}

	public static TrustedServiceFilter createFilterByCountry(String countryCode) {
		return new ServiceByCountryFilter(countryCode);
	}

}
