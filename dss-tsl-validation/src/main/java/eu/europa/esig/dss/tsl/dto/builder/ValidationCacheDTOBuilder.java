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
package eu.europa.esig.dss.tsl.dto.builder;

import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.tsl.cache.state.CachedEntry;
import eu.europa.esig.dss.tsl.dto.ValidationCacheDTO;
import eu.europa.esig.dss.tsl.validation.ValidationResult;

import java.util.Date;
import java.util.List;

/**
 * Builds {@code ValidationCacheDTO}
 */
public class ValidationCacheDTOBuilder extends AbstractCacheDTOBuilder<ValidationResult> {

	/**
	 * Default constructor
	 *
	 * @param cachedEntry validation cache entry
	 */
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
			validationCacheDTO.setPotentialSigners(getPotentialSigners());
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
	
	private List<CertificateToken> getPotentialSigners() {
		return getResult().getPotentialSigners();
	}

}
