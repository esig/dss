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
package eu.europa.esig.dss.tsl.source;

import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.tsl.cache.CacheKey;
import eu.europa.esig.trustedlist.jaxb.tsl.TSPServiceType;
import eu.europa.esig.trustedlist.jaxb.tsl.TSPType;

import java.util.Objects;
import java.util.function.Predicate;

/**
 * Represent a Trusted List source
 */
public class TLSource {

	/**
	 * URL
	 */
	private String url;

	/**
	 * Signing certificates for the current TL
	 */
	private CertificateSource certificateSource;

	/**
	 * Allow to filter the collected trust service provider(s) with a predicate
	 * 
	 * Default : all trust service providers are selected
	 */
	private Predicate<TSPType> trustServiceProviderPredicate;

	/**
	 * Allow to filter the collected trust service(s) with a predicate
	 * 
	 * Default : all trust services are selected
	 */
	private Predicate<TSPServiceType> trustServicePredicate;
	
	/**
	 * The cached CacheKey value (the key is computed from url parameter)
	 */
	private CacheKey cacheKey;

	/**
	 * Gets the TL URL
	 *
	 * @return {@link String}
	 */
	public String getUrl() {
		return url;
	}

	/**
	 * Sets the TL access URL
	 *
	 * @param url {@link String}
	 */
	public void setUrl(String url) {
		Objects.requireNonNull(url, "URL cannot be null.");
		this.url = url;
	}

	/**
	 * Gets the certificate source to be used for TL validation
	 *
	 * @return {@link CertificateSource}
	 */
	public CertificateSource getCertificateSource() {
		return certificateSource;
	}

	/**
	 * Sets the certificate source to be used for TL validation
	 *
	 * @param certificateSource {@link CertificateSource}
	 */
	public void setCertificateSource(CertificateSource certificateSource) {
		Objects.requireNonNull(certificateSource);
		this.certificateSource = certificateSource;
	}

	/**
	 * Gets a predicate to filter TrustServiceProviders
	 *
	 * @return {@link Predicate}
	 */
	public Predicate<TSPType> getTrustServiceProviderPredicate() {
		return trustServiceProviderPredicate;
	}

	/**
	 * Sets a  predicate to filter TrustServiceProviders
	 *
	 * @param trustServiceProviderPredicate {@link Predicate}
	 */
	public void setTrustServiceProviderPredicate(Predicate<TSPType> trustServiceProviderPredicate) {
		this.trustServiceProviderPredicate = trustServiceProviderPredicate;
	}

	/**
	 * Gets a predicate to filter TrustServices
	 *
	 * @return {@link Predicate}
	 */
	public Predicate<TSPServiceType> getTrustServicePredicate() {
		return trustServicePredicate;
	}

	/**
	 * Sets a  predicate to filter TrustServices
	 *
	 * @param trustServicePredicate {@link Predicate}
	 */
	public void setTrustServicePredicate(Predicate<TSPServiceType> trustServicePredicate) {
		this.trustServicePredicate = trustServicePredicate;
	}

	/**
	 * Gets the TL cache key
	 *
	 * @return {@link CacheKey}
	 */
	public CacheKey getCacheKey() {
		if (cacheKey == null) {
			cacheKey = new CacheKey(url);
		}
		return cacheKey;
	}

}
