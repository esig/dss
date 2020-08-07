package eu.europa.esig.dss.model;

public interface SerializableCounterSignatureParameters extends SerializableSignatureParameters {
	
	/**
	 * Returns Id of a signature that needs to be counter signed
	 * 
	 * @return {@link String} signature id
	 */
	String getSigningSignatureId();
	
	/**
	 * Sets the Id of a signature to be counter signed
	 * NOTE: if non signature Id is defined, counter signs the first available signature
	 * 
	 * @param signatureId {@link String} id of a signature to be counter signed
	 */
	void setSigningSignatureId(String signatureId);

}
