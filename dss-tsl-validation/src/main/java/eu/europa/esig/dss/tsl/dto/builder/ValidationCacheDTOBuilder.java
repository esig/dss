package eu.europa.esig.dss.tsl.dto.builder;

import java.util.Date;

import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.tsl.cache.state.CachedEntry;
import eu.europa.esig.dss.tsl.dto.ValidationCacheDTO;
import eu.europa.esig.dss.tsl.validation.ValidationResult;

public class ValidationCacheDTOBuilder extends AbstractCacheDTOBuilder<ValidationResult> {
	
	public ValidationCacheDTOBuilder(final CachedEntry<ValidationResult> cachedEntry) {
		super(cachedEntry);
	}
	
	@Override
	public ValidationCacheDTO build() {
		ValidationCacheDTO validationCacheDTO = new ValidationCacheDTO(super.build());
		if (isResultExist()) {
			validationCacheDTO.setIndication(getIndication());
			validationCacheDTO.setSubIndication(getSubIndication());
			validationCacheDTO.setSigningTime(getSigningTime());
			validationCacheDTO.setSigningCertificate(getSigningCertificate());
		}
		return validationCacheDTO;
	}
	
	private Indication getIndication() {
		return getResult().getIndication();
	}
	
	private SubIndication getSubIndication() {
		return getResult().getSubIndication();
	}
	
	private Date getSigningTime() {
		return getResult().getSigningTime();
	}
	
	private CertificateToken getSigningCertificate() {
		return getResult().getSigningCertificate();
	}

}
