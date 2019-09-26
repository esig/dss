package eu.europa.esig.dss.tsl.cache;

import java.util.Date;

import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.model.x509.CertificateToken;

public class ValidationCacheDataAccess extends AbstractCacheDataAccess<ValidationCache> {
	
	public ValidationCacheDataAccess(final ValidationCache validationCache, final CacheKey cacheKey) {
		super(validationCache, cacheKey);
	}
	
	public Indication getIndication() {
		return cache.getIndication(getCacheKey());
	}
	
	public SubIndication getSubIndication() {
		return cache.getSubIndication(getCacheKey());
	}
	
	public Date getSigningTime() {
		return cache.getSigningTime(getCacheKey());
	}
	
	public CertificateToken getSigningCertificate() {
		return cache.getSigningCertificate(getCacheKey());
	}

}
