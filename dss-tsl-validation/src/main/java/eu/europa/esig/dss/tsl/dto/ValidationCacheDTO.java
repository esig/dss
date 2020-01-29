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

import java.util.Date;
import java.util.List;

import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.tsl.ValidationInfoRecord;

public class ValidationCacheDTO extends AbstractCacheDTO implements ValidationInfoRecord {

	private static final long serialVersionUID = -4534009898186648431L;
	
	private Indication indication;
	private SubIndication subIndication;
	private Date signingTime;
	private CertificateToken signingCertificate;
	private List<CertificateToken> potentialSigners;

	public ValidationCacheDTO() {}
	
	public ValidationCacheDTO(AbstractCacheDTO cacheDTO) {
		super(cacheDTO);
	}
	
	@Override
	public Indication getIndication() {
		return indication;
	}
	
	public void setIndication(Indication indication) {
		this.indication = indication;
	}

	@Override
	public SubIndication getSubIndication() {
		return subIndication;
	}
	
	public void setSubIndication(SubIndication subIndication) {
		this.subIndication = subIndication;
	}

	@Override
	public Date getSigningTime() {
		return signingTime;
	}
	
	public void setSigningTime(Date signingTime) {
		this.signingTime = signingTime;
	}

	@Override
	public CertificateToken getSigningCertificate() {
		return signingCertificate;
	}

	public void setSigningCertificate(CertificateToken signingCertificate) {
		this.signingCertificate = signingCertificate;
	}

	@Override
	public List<CertificateToken> getPotentialSigners() {
		return potentialSigners;
	}

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
