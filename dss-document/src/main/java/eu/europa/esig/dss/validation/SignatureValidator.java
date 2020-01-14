package eu.europa.esig.dss.validation;

import java.util.List;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.x509.CertificateToken;

public interface SignatureValidator extends DocumentValidator {

	/**
	 * Retrieves the signatures found in the document
	 *
	 * @return a list of AdvancedSignatures for validation purposes
	 */
	List<AdvancedSignature> getSignatures();

	/**
	 * Sets the {@code List} of {@code DSSDocument} containing the original contents to sign, for detached signature
	 * scenarios.
	 *
	 * @param detachedContent
	 *            the {@code List} of {@code DSSDocument} to set
	 */
	void setDetachedContents(final List<DSSDocument> detachedContent);

	/**
	 * This method allows to define the signing certificate. It is useful in the case of non AdES signatures.
	 *
	 * @param x509Certificate
	 */
	void defineSigningCertificate(final CertificateToken x509Certificate);
	
	/**
	 * This method allows to set a provider for Signature policies
	 * 
	 * @param signaturePolicyProvider
	 */
	void setSignaturePolicyProvider(SignaturePolicyProvider signaturePolicyProvider);
	
	/**
	 * This method returns the signed document(s) without their signature(s)
	 *
	 * @param signatureId
	 *            the DSS ID of the signature to extract original signer data for
	 */
	List<DSSDocument> getOriginalDocuments(final String signatureId);

	/**
	 * This method returns the signed document(s) without their signature(s)
	 *
	 * @param advancedSignature
	 *            {@link AdvancedSignature} to find signer documents for
	 */
	List<DSSDocument> getOriginalDocuments(final AdvancedSignature advancedSignature);
	
}
