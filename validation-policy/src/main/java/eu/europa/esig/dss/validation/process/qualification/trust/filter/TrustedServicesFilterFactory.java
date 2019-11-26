/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * 
 * This file is part of the "DSS - Digital Signature Services" project.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.validation.process.qualification.trust.filter;

import java.util.Date;
import java.util.Set;

import eu.europa.esig.dss.diagnostic.CertificateWrapper;

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

	public static TrustedServiceFilter createFilterByUrls(Set<String> urls) {
		return new ServiceByTLUrlFilter(urls);
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
