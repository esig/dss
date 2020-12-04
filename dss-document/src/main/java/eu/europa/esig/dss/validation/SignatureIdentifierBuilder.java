package eu.europa.esig.dss.validation;

/**
 * Builds a deterministic Signature Identifier for the produced reports
 */
public interface SignatureIdentifierBuilder {
	
	/**
	 * Builds {@code SignatureIdentifier} for the provided {@code AdvancedSignature}
	 * 
	 * @return {@link SignatureIdentifier}
	 */
	SignatureIdentifier build();

}
