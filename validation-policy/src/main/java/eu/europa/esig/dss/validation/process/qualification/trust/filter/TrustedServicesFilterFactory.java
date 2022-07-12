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

import eu.europa.esig.dss.diagnostic.CertificateWrapper;

import java.util.Date;
import java.util.Set;

/**
 * Creates a {@code TrustedServiceFilter}
 *
 */
public final class TrustedServicesFilterFactory {

	/**
	 * Default constructor
	 */
	private TrustedServicesFilterFactory() {
	}

	/**
	 * Creates a TrustedService filter by 'granted' status
	 *
	 * @return {@link TrustedServiceFilter}
	 */
	public static TrustedServiceFilter createFilterByGranted() {
		return new GrantedServiceFilter();
	}

	/**
	 * Creates a TrustedService filter by 'CA/QC' identifier
	 *
	 * @return {@link TrustedServiceFilter}
	 */
	public static TrustedServiceFilter createFilterByCaQc() {
		return new CaQcServiceFilter();
	}

	/**
	 * Creates a TrustedService filter by 'TSA/QTST' identifier
	 *
	 * @return {@link TrustedServiceFilter}
	 */
	public static TrustedServiceFilter createFilterByQTST() {
		return new QTSTServiceFilter();
	}

	/**
	 * Creates a TrustedService filter by date
	 *
	 * @param date {@link Date} to filter trusted services by
	 * @return {@link TrustedServiceFilter}
	 */
	public static TrustedServiceFilter createFilterByDate(Date date) {
		return new ServiceByDateFilter(date);
	}

	/**
	 * Creates a TrustedService filter by country code
	 *
	 * @param countryCode {@link String} to filter trusted services by
	 * @return {@link TrustedServiceFilter}
	 */
	public static TrustedServiceFilter createFilterByCountry(String countryCode) {
		return new ServiceByCountryFilter(countryCode);
	}

	/**
	 * Creates a TrustedService filter by country codes
	 *
	 * @param countryCodes a set of {@link String}s to filter trusted services by
	 * @return {@link TrustedServiceFilter}
	 */
	public static TrustedServiceFilter createFilterByCountries(Set<String> countryCodes) {
		return new ServiceByCountryFilter(countryCodes);
	}

	/**
	 * Creates a TrustedService filter by urls
	 *
	 * @param urls a set of {@link String}s to filter trusted services by
	 * @return {@link TrustedServiceFilter}
	 */
	public static TrustedServiceFilter createFilterByUrls(Set<String> urls) {
		return new ServiceByTLUrlFilter(urls);
	}

	/**
	 * Creates a TrustedService filter by end-entity certificate
	 *
	 * @param endEntityCertificate {@link CertificateWrapper} to filter trusted services by
	 * @return {@link TrustedServiceFilter}
	 */
	public static TrustedServiceFilter createUniqueServiceFilter(CertificateWrapper endEntityCertificate) {
		return new UniqueServiceFilter(endEntityCertificate);
	}

	/**
	 * Creates a TrustedService filter by the type as in the given certificate
	 *
	 * @param certificate {@link CertificateWrapper} to filter trusted services by its type
	 * @return {@link TrustedServiceFilter}
	 */
	public static TrustedServiceFilter createFilterByCertificateType(CertificateWrapper certificate) {
		return new ServiceByCertificateTypeFilter(certificate);
	}

	/**
	 * Creates a TrustedService filter by status consistency
	 *
	 * @return {@link TrustedServiceFilter}
	 */
	public static TrustedServiceFilter createConsistentServiceByStatusFilter() {
		return new ConsistentServiceByStatusFilter();
	}

	/**
	 * Creates a TrustedService filter by QC consistency
	 *
	 * @return {@link TrustedServiceFilter}
	 */
	public static TrustedServiceFilter createConsistentServiceByQCFilter() {
		return new ConsistentServiceByQCFilter();
	}

	/**
	 * Creates a TrustedService filter by QC consistency
	 *
	 * @return {@link TrustedServiceFilter}
	 */
	public static TrustedServiceFilter createConsistentServiceByCertificateTypeFilter() {
		return new ConsistentServiceByCertificateTypeFilter();
	}

	/**
	 * Creates a TrustedService filter by QSCD consistency
	 *
	 * @return {@link TrustedServiceFilter}
	 */
	public static TrustedServiceFilter createConsistentServiceByQSCDFilter() {
		return new ConsistentServiceByQSCDFilter();
	}

	/**
	 * Creates a TrustedService filter by MRA enacted
	 *
	 * @return {@link TrustedServiceFilter}
	 */
	public static TrustedServiceFilter createMRAEnactedFilter() {
		return new ServiceByMRAEnactedFilter();
	}

	/**
	 * Creates a TrustedService filter by MRA equivalence starting date
	 *
	 * @param date {@link Date} to filter trusted services by
	 * @return {@link TrustedServiceFilter}
	 */
	public static TrustedServiceFilter createFilterByMRAEquivalenceStartingDate(Date date) {
		return new ServiceByMRAEquivalenceStartingDateFilter(date);
	}

}
