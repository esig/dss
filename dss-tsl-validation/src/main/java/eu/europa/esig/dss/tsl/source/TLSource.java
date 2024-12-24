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
package eu.europa.esig.dss.tsl.source;

import eu.europa.esig.dss.model.tsl.TrustServiceStatusAndInformationExtensions;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.tsl.cache.CacheKey;
import eu.europa.esig.trustedlist.jaxb.tsl.TSPServiceType;
import eu.europa.esig.trustedlist.jaxb.tsl.TSPType;

import java.util.List;
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
	 * Defines whether an SDI can be considered as a trust anchor during the given period of time
	 */
	private Predicate<TrustServiceStatusAndInformationExtensions> trustAnchorValidityPredicate;

	/**
	 * List of TL Versions accepted for the current TLSource. When defined, an error is returned on structure validation.
	 */
	private List<Integer> tlVersions;
	
	/**
	 * The cached CacheKey value (the key is computed from url parameter)
	 */
	private CacheKey cacheKey;

	/**
	 * Default constructor instantiating object with null values
	 */
	public TLSource() {
		// empty
	}

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
	 * Gets a predicate for filtering {@code TrustServiceStatusAndInformationExtensions} in order to define
	 * an acceptability period of a corresponding SDI as a trust anchor.
	 *
	 * @return trust anchor validity predicate
	 */
	public Predicate<TrustServiceStatusAndInformationExtensions> getTrustAnchorValidityPredicate() {
		return trustAnchorValidityPredicate;
	}

	/**
	 * Sets a predicate allowing to filter {@code TrustServiceStatusAndInformationExtensions} in order to define
	 * an acceptability period of a corresponding SDI as a trust anchor.
	 * If the predicate is defined and condition fails, the SDI will not be treated as a trust anchor
	 * during the validation process.
	 *
	 * @param trustAnchorValidityPredicate trust anchor validity predicate
	 */
	public void setTrustAnchorValidityPredicate(Predicate<TrustServiceStatusAndInformationExtensions> trustAnchorValidityPredicate) {
		this.trustAnchorValidityPredicate = trustAnchorValidityPredicate;
	}

	/**
	 * Gets a list of TL versions to be accepted for the current TL/LOTL source
	 *
	 * @return a list of {@link Integer}s representing acceptable XML TL versions
	 */
	public List<Integer> getTLVersions() {
		return tlVersions;
	}

	/**
	 * Sets a list of acceptable XML Trusted List versions.
	 * When defined, an error message to be returned on structural validation.
	 * If not defined, no structural validation is performed.
	 *
	 * @param tlVersions a list of {@link Integer}s representing a supported TL versions to be validated
	 */
	public void setTLVersions(List<Integer> tlVersions) {
		this.tlVersions = tlVersions;
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
