package eu.europa.esig.dss.model;

/**
 * The interface contains the common methods for counter signature parameters
 */
public interface SerializableCounterSignatureParameters extends SerializableSignatureParameters {
	
	/**
	 * Returns Id of a signature that needs to be counter signed
	 * 
	 * @return {@link String} signature id
	 */
	String getSignatureIdToCounterSign();
	
	/**
	 * Sets the Id of a signature to be counter signed
	 * 
	 * @param signatureId {@link String} id of a signature to be counter signed
	 */
	void setSignatureIdToCounterSign(String signatureId);

}
