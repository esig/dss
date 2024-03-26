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
package eu.europa.esig.dss.tsl.dto;

import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.tsl.ValidationInfoRecord;

import java.util.Date;
import java.util.List;

/**
 * The validation record DTO
 */
public class ValidationCacheDTO extends AbstractCacheDTO implements ValidationInfoRecord {

	private static final long serialVersionUID = -4534009898186648431L;

	/** The validation Indication */
	private Indication indication;

	/** The validation SubIndication */
	private SubIndication subIndication;

	/** The claimed signing time */
	private Date signingTime;

	/** The signing certificate */
	private CertificateToken signingCertificate;

	/** Signing candidates */
	private List<CertificateToken> potentialSigners;

	/**
	 * Default constructor
	 */
	public ValidationCacheDTO() {
		// empty
	}

	/**
	 * Copies the cache DTO
	 *
	 * @param cacheDTO {@link AbstractCacheDTO}
	 */
	public ValidationCacheDTO(AbstractCacheDTO cacheDTO) {
		super(cacheDTO);
	}
	
	@Override
	public Indication getIndication() {
		return indication;
	}

	/**
	 * Sets the validation Indication
	 *
	 * @param indication {@link Indication}
	 */
	public void setIndication(Indication indication) {
		this.indication = indication;
	}

	@Override
	public SubIndication getSubIndication() {
		return subIndication;
	}

	/**
	 * Sets the validation SubIndication
	 *
	 * @param subIndication {@link SubIndication}
	 */
	public void setSubIndication(SubIndication subIndication) {
		this.subIndication = subIndication;
	}

	@Override
	public Date getSigningTime() {
		return signingTime;
	}

	/**
	 * Sets the claimed signing time
	 *
	 * @param signingTime {@link Date}
	 */
	public void setSigningTime(Date signingTime) {
		this.signingTime = signingTime;
	}

	@Override
	public CertificateToken getSigningCertificate() {
		return signingCertificate;
	}

	/**
	 * Sets the signing certificate token
	 *
	 * @param signingCertificate {@link CertificateToken}
	 */
	public void setSigningCertificate(CertificateToken signingCertificate) {
		this.signingCertificate = signingCertificate;
	}

	@Override
	public List<CertificateToken> getPotentialSigners() {
		return potentialSigners;
	}

	/**
	 * Sets a list of signing candidates
	 *
	 * @param potentialSigners a list of {@link CertificateToken}s
	 */
	public void setPotentialSigners(List<CertificateToken> potentialSigners) {
		this.potentialSigners = potentialSigners;
	}

	@Override
	public boolean isValid() {
		return Indication.TOTAL_PASSED.equals(indication);
	}

	@Override
	public boolean isIndeterminate() {
		return Indication.INDETERMINATE.equals(indication);
	}

	@Override
	public boolean isInvalid() {
		return Indication.TOTAL_FAILED.equals(indication);
	}

}
