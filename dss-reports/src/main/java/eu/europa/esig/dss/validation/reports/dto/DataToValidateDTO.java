package eu.europa.esig.dss.validation.reports.dto;

import eu.europa.esig.dss.RemoteDocument;
import eu.europa.esig.jaxb.policy.ConstraintsParameters;

public class DataToValidateDTO {

	private RemoteDocument signedDocument;
	private RemoteDocument originalDocument;
	private ConstraintsParameters policy;
	
	public DataToValidateDTO() {
	}
	
	public DataToValidateDTO(RemoteDocument signedDocument, RemoteDocument originalDocument, ConstraintsParameters policy) {
		this.signedDocument = signedDocument;
		this.originalDocument = originalDocument;
		this.policy = policy;
	}
	
	public RemoteDocument getSignedDocument() {
		return signedDocument;
	}
	public void setSignedDocument(RemoteDocument signedDocument) {
		this.signedDocument = signedDocument;
	}
	public RemoteDocument getOriginalDocument() {
		return originalDocument;
	}
	public void setOriginalDocument(RemoteDocument originalDocument) {
		this.originalDocument = originalDocument;
	}
	public ConstraintsParameters getPolicy() {
		return policy;
	}
	public void setPolicy(ConstraintsParameters policy) {
		this.policy = policy;
	}
}
