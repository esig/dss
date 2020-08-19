package eu.europa.esig.dss.validation;

public interface SignatureIdentifierBuilder {
	
	/**
	 * Builds {@code SignatureIdentifier} for the provided {@code AdvancedSignature}
	 * 
	 * @return {@link SignatureIdentifier}
	 */
	SignatureIdentifier build();

}
