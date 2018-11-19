package eu.europa.esig.dss;

import java.util.Arrays;
import java.util.List;

public class DataToValidateDTO {

	/**
	 * The document which contains the signature(s)
	 */
	private RemoteDocument signedDocument;

	/**
	 * The original file(s) in case of detached signature
	 */
	private List<RemoteDocument> originalDocuments;

	/**
	 * The custom validation policy to use
	 */
	private RemoteDocument policy;

	/**
	 * The signature to operate on
	 */
	private String signatureId;

	public DataToValidateDTO() {
	}

	public DataToValidateDTO(RemoteDocument signedDocument, RemoteDocument originalDocument, RemoteDocument policy) {
		this(signedDocument, Arrays.asList(originalDocument), policy);
	}

	public DataToValidateDTO(RemoteDocument signedDocument, List<RemoteDocument> originalDocuments, RemoteDocument policy) {
		this.signedDocument = signedDocument;
		this.originalDocuments = originalDocuments;
		this.policy = policy;
	}

	public DataToValidateDTO(RemoteDocument signedDocument, RemoteDocument originalDocument, RemoteDocument policy, String signatureId) {
		this(signedDocument, Arrays.asList(originalDocument), policy, signatureId);
	}

	public DataToValidateDTO(RemoteDocument signedDocument, List<RemoteDocument> originalDocuments, RemoteDocument policy, String signatureId) {
		this.signedDocument = signedDocument;
		this.originalDocuments = originalDocuments;
		this.policy = policy;
		this.signatureId = signatureId;
	}

	public RemoteDocument getSignedDocument() {
		return signedDocument;
	}

	public void setSignedDocument(RemoteDocument signedDocument) {
		this.signedDocument = signedDocument;
	}

	public List<RemoteDocument> getOriginalDocuments() {
		return originalDocuments;
	}

	public void setOriginalDocuments(List<RemoteDocument> originalDocuments) {
		this.originalDocuments = originalDocuments;
	}

	public RemoteDocument getPolicy() {
		return policy;
	}

	public void setPolicy(RemoteDocument policy) {
		this.policy = policy;
	}

	public String getSignatureId() {
		return signatureId;
	}

	public void setSignatureId(String signatureId) {
		this.signatureId = signatureId;
	}

}
