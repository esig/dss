/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.validation.process.qualification.trust.filter;

import eu.europa.esig.dss.diagnostic.CertificateWrapper;

import java.util.Date;
import java.util.Set;

/**
 * Creates a {@code TrustServiceFilter}
 *
 */
public final class TrustServicesFilterFactory {

	/**
	 * Default constructor
	 */
	private TrustServicesFilterFactory() {
		// empty
	}

	/**
	 * Creates a TrustService filter by 'granted' status
	 *
	 * @return {@link TrustServiceFilter}
	 */
	public static TrustServiceFilter createFilterByGranted() {
		return new GrantedServiceFilter();
	}

	/**
	 * Creates a TrustService filter by 'CA/QC' identifier
	 *
	 * @return {@link TrustServiceFilter}
	 */
	public static TrustServiceFilter createFilterByCaQc() {
		return new CaQcServiceFilter();
	}

	/**
	 * Creates a TrustService filter by 'TSA/QTST' identifier
	 *
	 * @return {@link TrustServiceFilter}
	 */
	public static TrustServiceFilter createFilterByQTST() {
		return new QTSTServiceFilter();
	}

	/**
	 * Creates a TrustService filter by date
	 *
	 * @param date {@link Date} to filter trusted services by
	 * @return {@link TrustServiceFilter}
	 */
	public static TrustServiceFilter createFilterByDate(Date date) {
		return new ServiceByDateFilter(date);
	}

	/**
	 * Creates a TrustService filter by country code
	 *
	 * @param countryCode {@link String} to filter trusted services by
	 * @return {@link TrustServiceFilter}
	 */
	public static TrustServiceFilter createFilterByCountry(String countryCode) {
		return new ServiceByCountryFilter(countryCode);
	}

	/**
	 * Creates a TrustService filter by country codes
	 *
	 * @param countryCodes a set of {@link String}s to filter trusted services by
	 * @return {@link TrustServiceFilter}
	 */
	public static TrustServiceFilter createFilterByCountries(Set<String> countryCodes) {
		return new ServiceByCountryFilter(countryCodes);
	}

	/**
	 * Creates a TrustService filter by urls
	 *
	 * @param urls a set of {@link String}s to filter trusted services by
	 * @return {@link TrustServiceFilter}
	 */
	public static TrustServiceFilter createFilterByUrls(Set<String> urls) {
		return new ServiceByTLUrlFilter(urls);
	}

	/**
	 * Creates a TrustService filter by end-entity certificate
	 *
	 * @param endEntityCertificate {@link CertificateWrapper} to filter trusted services by
	 * @return {@link TrustServiceFilter}
	 */
	public static TrustServiceFilter createUniqueServiceFilter(CertificateWrapper endEntityCertificate) {
		return new UniqueServiceFilter(endEntityCertificate);
	}

	/**
	 * Creates a TrustService filter by the type as in the given certificate
	 *
	 * @param certificate {@link CertificateWrapper} to filter trusted services by its type
	 * @return {@link TrustServiceFilter}
	 */
	public static TrustServiceFilter createFilterByCertificateType(CertificateWrapper certificate) {
		return new ServiceByCertificateTypeFilter(certificate);
	}

	/**
	 * Creates a TrustService filter by status consistency
	 *
	 * @return {@link TrustServiceFilter}
	 */
	public static TrustServiceFilter createConsistentServiceByStatusFilter() {
		return new ConsistentServiceByStatusFilter();
	}

	/**
	 * Creates a TrustService filter by QC consistency
	 *
	 * @return {@link TrustServiceFilter}
	 */
	public static TrustServiceFilter createConsistentServiceByQCFilter() {
		return new ConsistentServiceByQCFilter();
	}

	/**
	 * Creates a TrustService filter by QC consistency
	 *
	 * @return {@link TrustServiceFilter}
	 */
	public static TrustServiceFilter createConsistentServiceByCertificateTypeFilter() {
		return new ConsistentServiceByCertificateTypeFilter();
	}

	/**
	 * Creates a TrustService filter by QSCD consistency
	 *
	 * @return {@link TrustServiceFilter}
	 */
	public static TrustServiceFilter createConsistentServiceByQSCDFilter() {
		return new ConsistentServiceByQSCDFilter();
	}

	/**
	 * Creates a TrustService filter by MRA enacted
	 *
	 * @return {@link TrustServiceFilter}
	 */
	public static TrustServiceFilter createMRAEnactedFilter() {
		return new ServiceByMRAEnactedFilter();
	}

	/**
	 * Creates a TrustService filter by MRA equivalence starting date
	 *
	 * @param date {@link Date} to filter trusted services by
	 * @return {@link TrustServiceFilter}
	 */
	public static TrustServiceFilter createFilterByMRAEquivalenceStartingDate(Date date) {
		return new ServiceByMRAEquivalenceStartingDateFilter(date);
	}

}
