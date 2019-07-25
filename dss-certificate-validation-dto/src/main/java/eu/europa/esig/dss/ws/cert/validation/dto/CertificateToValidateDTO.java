package eu.europa.esig.dss.ws.cert.validation.dto;

import java.util.Date;
import java.util.List;

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

}
