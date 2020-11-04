package eu.europa.esig.dss.signature;

import java.io.Serializable;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.SerializableCounterSignatureParameters;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;

/**
 * This interface {@code CounterSignatureService} provides operations for a counter signature creation
 *
 */
public interface CounterSignatureService<CSP extends SerializableCounterSignatureParameters> extends Serializable {
	
	/**
	 * Retrieves the bytes of the data that need to be counter signed from {@code signatureDocument}.
	 * {@code signatureDocument} shall be a valid signature of the same type
	 * 
	 * @param signatureDocument 
	 *           {@link DSSDocument} representing the original signature to be counter signed
	 * @param parameters
	 *            set of the driving signing parameters for a counter signature
	 * @return {@link ToBeSigned} to be counter signed byte array (signature value retrieved from the {@code signatureDocument})
	 */
	ToBeSigned getDataToBeCounterSigned(final DSSDocument signatureDocument, final CSP parameters);

	/**
	 * Counter signs the {@code signatureDocument} with the provided signatureValue.
	 *
	 * @param signatureDocument
	 *            {@link DSSDocument} to be counter signed
	 * @param parameters
	 *            set of the driving signing parameters for a counter signature
	 * @param signatureValue
	 *            {@link SignatureValue} the signature value to incorporate
	 * @return {@link DSSDocument} the signature document enveloping a newly created counter signature
	 */
	DSSDocument counterSignSignature(final DSSDocument signatureDocument, final CSP parameters, final SignatureValue signatureValue);

}
