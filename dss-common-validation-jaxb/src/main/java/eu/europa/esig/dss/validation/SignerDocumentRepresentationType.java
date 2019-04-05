package eu.europa.esig.dss.validation;

/**
 * Indicates type of data what was used for the signature validation
 */
public enum SignerDocumentRepresentationType {
	
	/**
	 * Original document that has been signed
	 */
	ORIGINAL_DOCUMENT,
	
	/**
	 * Digest representation of the original signed document
	 */
	DIGEST_DOCUMENT,

}
