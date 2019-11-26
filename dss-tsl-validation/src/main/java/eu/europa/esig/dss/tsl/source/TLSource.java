package eu.europa.esig.dss.tsl.source;

import java.util.Objects;

import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.tsl.cache.CacheKey;
import eu.europa.esig.dss.tsl.function.TrustServicePredicate;
import eu.europa.esig.dss.tsl.function.TrustServiceProviderPredicate;

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
	private TrustServiceProviderPredicate trustServiceProviderPredicate;

	/**
	 * Allow to filter the collected trust service(s) with a predicate
	 * 
	 * Default : all trust services are selected
	 */
	private TrustServicePredicate trustServicePredicate;
	
	/**
	 * The cached CacheKey value (the key is computed from url parameter)
	 */
	private CacheKey cacheKey;
	
	public String getUrl() {
		return url;
	}
	
	public void setUrl(String url) {
		Objects.requireNonNull(url, "URL cannot be null.");
		this.url = url;
	}

	public CertificateSource getCertificateSource() {
		return certificateSource;
	}

	public void setCertificateSource(CertificateSource certificateSource) {
		Objects.requireNonNull(certificateSource);
		this.certificateSource = certificateSource;
	}

	public TrustServiceProviderPredicate getTrustServiceProviderPredicate() {
		return trustServiceProviderPredicate;
	}

	public void setTrustServiceProviderPredicate(TrustServiceProviderPredicate trustServiceProviderPredicate) {
		this.trustServiceProviderPredicate = trustServiceProviderPredicate;
	}

	public TrustServicePredicate getTrustServicePredicate() {
		return trustServicePredicate;
	}

	public void setTrustServicePredicate(TrustServicePredicate trustServicePredicate) {
		this.trustServicePredicate = trustServicePredicate;
	}

	public CacheKey getCacheKey() {
		if (cacheKey == null) {
			cacheKey = new CacheKey(url);
		}
		return cacheKey;
	}

}
