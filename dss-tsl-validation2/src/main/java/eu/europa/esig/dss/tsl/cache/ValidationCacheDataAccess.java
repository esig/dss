package eu.europa.esig.dss.tsl.cache;

import java.util.Date;

import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.model.x509.CertificateToken;

public class ValidationCacheDataAccess extends AbstractCacheDataAccess<ValidationCache> {
	
	public ValidationCacheDataAccess(ValidationCache validationCache) {
		super(validationCache);
	}
	
	public Indication getIndication(CacheKey cacheKey) {
		return cache.getIndication(cacheKey);
	}
	
	public SubIndication getSubIndication(CacheKey cacheKey) {
		return cache.getSubIndication(cacheKey);
	}
	
	public Date getSigningTime(CacheKey cacheKey) {
		return cache.getSigningTime(cacheKey);
	}
	
	public CertificateToken getSigningCertificate(CacheKey cacheKey) {
		return cache.getSigningCertificate(cacheKey);
	}

}
