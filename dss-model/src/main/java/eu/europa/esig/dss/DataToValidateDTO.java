package eu.europa.esig.dss;

public class DataToValidateDTO {

	/**
	 * The document which contains the signature(s)
	 */
	private RemoteDocument signedDocument;

	/**
	 * The original file in case of detached signature
	 */
	private RemoteDocument originalDocument;

	/**
	 * The custom validation policy to use
	 */
	private RemoteDocument policy;

	public DataToValidateDTO() {
	}

	public DataToValidateDTO(RemoteDocument signedDocument, RemoteDocument originalDocument, RemoteDocument policy) {
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

	public RemoteDocument getPolicy() {
		return policy;
	}

	public void setPolicy(RemoteDocument policy) {
		this.policy = policy;
	}

}
