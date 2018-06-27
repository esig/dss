package eu.europa.esig.dss.validation.process.qualification.trust.filter;

import java.util.Date;
import java.util.Set;

import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;

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

	public static TrustedServiceFilter createFilterByCountries(Set<String> countryCodes) {
		return new ServiceByCountryFilter(countryCodes);
	}

	public static TrustedServiceFilter createUniqueServiceFilter(CertificateWrapper endEntityCertificate) {
		return new UniqueServiceFilter(endEntityCertificate);
	}

	public static TrustedServiceFilter createConsistentServiceFilter() {
		return new FullyConsistentServiceFilter();
	}

	public static TrustedServiceFilter createFilterByCertificateType(CertificateWrapper certificate) {
		return new ServiceByCertificateTypeFilter(certificate);
	}

}
