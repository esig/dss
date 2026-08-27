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
package eu.europa.esig.dss.lote.source;

import eu.europa.esig.dss.model.lote.ServiceStatusAndInformationExtensions;
import eu.europa.esig.dss.model.lote.TrustedEntity;
import eu.europa.esig.dss.model.lote.TrustedEntityService;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.validation.job.cache.CacheKey;
import eu.europa.esig.dss.validation.job.source.DocumentSource;

import java.util.Objects;
import java.util.function.Predicate;

/**
 * Represent a LoTE source definition
 *
 */
public class LoTESource extends DocumentSource {

	/**
	 * URL
	 */
	private String url;

	/**
	 * Signing certificates for the current TL
	 */
	private CertificateSource certificateSource;

	/**
	 * Allow to filter the collected trust entities with a predicate
	 * <p>
	 * Default : all trust entities are selected
	 */
	private Predicate<TrustedEntity> trustedEntityPredicate;

	/**
	 * Allow to filter the collected trusted service(s) with a predicate
	 * <p>
	 * Default : all trusted services are selected
	 */
	private Predicate<TrustedEntityService> trustedServicePredicate;

	/**
	 * Defines whether an SDI can be considered as a trust anchor during the given period of time
	 */
	private Predicate<ServiceStatusAndInformationExtensions> trustAnchorValidityPredicate;
	
	/**
	 * The cached CacheKey value (the key is computed from url parameter)
	 */
	private CacheKey cacheKey;

	/**
	 * Default constructor instantiating object with null values
	 */
	public LoTESource() {
		// empty
	}

	/**
	 * Gets the TL URL
	 *
	 * @return {@link String}
	 */
	@Override
	public String getUrl() {
		return url;
	}

	/**
	 * Sets the TL access URL
	 *
	 * @param url {@link String}
	 */
	@Override
	public void setUrl(String url) {
		Objects.requireNonNull(url, "URL cannot be null.");
		this.url = url;
	}

	/**
	 * Gets the certificate source to be used for TL validation
	 *
	 * @return {@link CertificateSource}
	 */
	@Override
	public CertificateSource getCertificateSource() {
		return certificateSource;
	}

	/**
	 * Sets the certificate source to be used for TL validation
	 *
	 * @param certificateSource {@link CertificateSource}
	 */
	@Override
	public void setCertificateSource(CertificateSource certificateSource) {
		Objects.requireNonNull(certificateSource);
		this.certificateSource = certificateSource;
	}

	/**
	 * Gets a predicate to filter Trusted Entities
	 *
	 * @return {@link Predicate}
	 */
	public Predicate<TrustedEntity> getTrustedEntityPredicate() {
		return trustedEntityPredicate;
	}

	/**
	 * Sets a  predicate to filter Trusted Entities
	 *
	 * @param trustedEntityPredicate {@link Predicate}
	 */
	public void setTrustedEntityPredicate(Predicate<TrustedEntity> trustedEntityPredicate) {
		this.trustedEntityPredicate = trustedEntityPredicate;
	}

	/**
	 * Gets a predicate to filter TrustedEntityServices
	 *
	 * @return {@link Predicate}
	 */
	public Predicate<TrustedEntityService> getTrustedServicePredicate() {
		return trustedServicePredicate;
	}

	/**
	 * Sets a  predicate to filter TrustedEntityServices
	 *
	 * @param trustedServicePredicate {@link Predicate}
	 */
	public void setTrustedServicePredicate(Predicate<TrustedEntityService> trustedServicePredicate) {
		this.trustedServicePredicate = trustedServicePredicate;
	}

	/**
	 * Gets a predicate for filtering {@code TrustServiceStatusAndInformationExtensions} in order to define
	 * an acceptability period of a corresponding SDI as a trust anchor.
	 *
	 * @return trust anchor validity predicate
	 */
	public Predicate<ServiceStatusAndInformationExtensions> getTrustAnchorValidityPredicate() {
		return trustAnchorValidityPredicate;
	}

	/**
	 * Sets a predicate allowing to filter {@code ServiceStatusAndInformationExtensions} in order to define
	 * an acceptability period of a corresponding SDI as a trust anchor.
	 * If the predicate is defined and condition fails, the SDI will not be treated as a trust anchor
	 * during the validation process.
	 *
	 * @param trustAnchorValidityPredicate trust anchor validity predicate
	 */
	public void setTrustAnchorValidityPredicate(Predicate<ServiceStatusAndInformationExtensions> trustAnchorValidityPredicate) {
		this.trustAnchorValidityPredicate = trustAnchorValidityPredicate;
	}

	/**
	 * Gets the TL cache key
	 *
	 * @return {@link CacheKey}
	 */
	@Override
	public CacheKey getCacheKey() {
		if (cacheKey == null) {
			cacheKey = new CacheKey(url);
		}
		return cacheKey;
	}

}
