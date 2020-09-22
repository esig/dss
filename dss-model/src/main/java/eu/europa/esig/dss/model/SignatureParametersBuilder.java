package eu.europa.esig.dss.model;

/**
 * A helper interface to hide complexity of a configuration for particular usages
 * and simplify the signature creation
 *
 * @param <SP> the {@code SerializableSignatureParameters} to be created
 */
public interface SignatureParametersBuilder<SP extends SerializableSignatureParameters> {
	
	/**
	 * Creates a Signature Parameters instance
	 * 
	 * @return {@code SP} signature parameters
	 */
	SP build();

}
