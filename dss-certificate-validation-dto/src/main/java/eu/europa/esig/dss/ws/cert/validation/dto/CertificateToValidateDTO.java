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
package eu.europa.esig.dss.ws.cert.validation.dto;

import java.util.Date;
import java.util.List;

import eu.europa.esig.dss.enumerations.TokenExtractionStategy;
import eu.europa.esig.dss.ws.dto.RemoteCertificate;

public class CertificateToValidateDTO {
	
	/**
	 * The certificate to be validated.
	 */
	private RemoteCertificate certificate;
	
	/**
	 * Allows to specify missing certificates in the chain.
	 * 
	 * OPTIONAL.
	 */
	private List<RemoteCertificate> certificateChain;
	
	/**
	 * Allows to specify a validation time different from the current time.
	 * 
	 * OPTIONAL.
	 */
	private Date validationTime;
	
	/**
	 * Allows to specify the token extraction to follow
	 * 
	 * NONE by default
	 */
	private TokenExtractionStategy tokenExtractionStategy = TokenExtractionStategy.NONE;

	public CertificateToValidateDTO() {
	}
	
	public CertificateToValidateDTO(RemoteCertificate certificate) {
		this(certificate, null, null);
	}
	
	public CertificateToValidateDTO(RemoteCertificate certificate, List<RemoteCertificate> certificateChain, Date validationTime) {
		this.certificate = certificate;
		this.certificateChain = certificateChain;
		this.validationTime = validationTime;
	}
	
	public CertificateToValidateDTO(RemoteCertificate certificate, List<RemoteCertificate> certificateChain,
			Date validationTime, TokenExtractionStategy tokenExtractionStategy) {
		this.certificate = certificate;
		this.certificateChain = certificateChain;
		this.validationTime = validationTime;
		this.tokenExtractionStategy = tokenExtractionStategy;
	}

	public RemoteCertificate getCertificate() {
		return certificate;
	}
	
	public void setCertificate(RemoteCertificate certificate) {
		this.certificate = certificate;
	}
	
	public List<RemoteCertificate> getCertificateChain() {
		return certificateChain;
	}
	
	public void setCertificateChain(List<RemoteCertificate> certificateChain) {
		this.certificateChain = certificateChain;
	}
	
	public Date getValidationTime() {
		return validationTime;
	}
	
	public void setValidationTime(Date validationTime) {
		this.validationTime = validationTime;
	}

	public TokenExtractionStategy getTokenExtractionStategy() {
		return tokenExtractionStategy;
	}

	public void setTokenExtractionStategy(TokenExtractionStategy tokenExtractionStategy) {
		this.tokenExtractionStategy = tokenExtractionStategy;
	}

}
