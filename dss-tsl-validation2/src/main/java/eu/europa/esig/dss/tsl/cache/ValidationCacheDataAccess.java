package eu.europa.esig.dss.tsl.cache;

import java.util.Date;

import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.tsl.cache.dto.ValidationCacheDTO;

public class ValidationCacheDataAccess extends AbstractCacheDataAccess<ValidationCache> {
	
	public ValidationCacheDataAccess(final ValidationCache validationCache, final CacheKey cacheKey) {
		super(validationCache, cacheKey);
	}
	
	@Override
	public ValidationCacheDTO getCacheDTO() {
		ValidationCacheDTO validationCacheDTO = new ValidationCacheDTO(super.getCacheDTO());
		validationCacheDTO.setIndication(getIndication());
		validationCacheDTO.setSubIndication(getSubIndication());
		validationCacheDTO.setSigningTime(getSigningTime());
		validationCacheDTO.setSigningCertificate(getSigningCertificate());
		return validationCacheDTO;
	}
	
	private Indication getIndication() {
		return cache.getIndication(getCacheKey());
	}
	
	private SubIndication getSubIndication() {
		return cache.getSubIndication(getCacheKey());
	}
	
	private Date getSigningTime() {
		return cache.getSigningTime(getCacheKey());
	}
	
	private CertificateToken getSigningCertificate() {
		return cache.getSigningCertificate(getCacheKey());
	}

}
