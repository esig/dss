package eu.europa.esig.dss.dto;

import java.sql.Date;
import java.util.List;

import eu.europa.esig.dss.RemoteDocument;

public class CertificateToValidateDTO {
	
	/**
	 * The certificate to be validated.
	 */
	private RemoteDocument certificate;
	
	/**
	 * Allows to specify missing certificates in the chain.
	 * 
	 * OPTIONAL.
	 */
	private List<RemoteDocument> certificateChain;
	
	/**
	 * Allows to specify a validation time different from the current time.
	 * 
	 * OPTIONAL.
	 */
	private Date validationTime;
	
	public CertificateToValidateDTO() {
	}
	
	public CertificateToValidateDTO(RemoteDocument certificate) {
		this(certificate, null, null);
	}
	
	public CertificateToValidateDTO(RemoteDocument certificate, List<RemoteDocument> certificateChain, Date validationTime) {
		this.certificate = certificate;
		this.certificateChain = certificateChain;
		this.validationTime = validationTime;
	}
	
	public RemoteDocument getCertificate() {
		return certificate;
	}
	
	public void setCertificate(RemoteDocument certificate) {
		this.certificate = certificate;
	}
	
	public List<RemoteDocument> getCertificateChain() {
		return certificateChain;
	}
	
	public void setCertificateChain(List<RemoteDocument> certificateChain) {
		this.certificateChain = certificateChain;
	}
	
	public Date getValidationTime() {
		return validationTime;
	}
	
	public void setValidationTime(Date validationTime) {
		this.validationTime = validationTime;
	}

}
