package eu.europa.esig.dss.jades.signature;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.MimeType;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;

public interface JAdESBuilder {
	
	/**
	 * Builds a signature
	 * 
	 * @param signatureValue {@link SignatureValue} to add to the signature
	 * @return {@link DSSDocument} containing JWS binaries
	 */
	DSSDocument build(SignatureValue signatureValue);

	/**
	 * Builds data to be signed by incorporating a detached payload when required (see 5.2.8.3 Mechanism ObjectIdByURI)
	 * 
	 * @return {@link String} representing the signature data to be signed result
	 */
	ToBeSigned buildDataToBeSigned();
	
	/**
	 * Returns MimeType of the produce signature by the builder
	 * 
	 * @return {@link MimeType}
	 */
	MimeType getMimeType();

}
