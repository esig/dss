package eu.europa.esig.dss.validation;

import java.util.List;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.validation.executor.SignatureProcessExecutor;

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
	 * Sets the {@code List} of {@code DSSDocument} containing the original container content for ASiC signatures.
	 *
	 * @param archiveContents
	 *            the {@code List} of {@code DSSDocument} to set
	 */
	void setContainerContents(final List<DSSDocument> archiveContents);

	/**
	 * Sets the {@code List} of {@code ManifestFile}s found in the signature file.
	 *
	 * @param manifestFiles
	 *            the {@code List} of {@code ManifestFile} to set
	 */
	void setManifestFiles(final List<ManifestFile> manifestFiles);

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
	 * Returns a default implementation of a process executor for signature validation
	 * 
	 * @return {@link SignatureProcessExecutor}
	 */
	@Override
	SignatureProcessExecutor getDefaultProcessExecutor();

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
	
	/**
	 * Prepares and fills {@code validationContext} for the signature validation
	 * @param validationContext {@link ValidationContext} to prepare
	 * @return list of {@link AdvancedSignature}s to be validated
	 */
	List<AdvancedSignature> prepareSignatureValidationContext(final ValidationContext validationContext);

	/**
	 * This method process the signature validation on the given {@code allSignatureList}
	 * 
	 * @param validationContext prepared and filled {@link ValidationContext}
	 * @param allSignatureList list of {@link AdvancedSignature}s to be validated
	 * @param structuralValidation specifies if structure of the signature must be validated
	 * @return list of validated {@link AdvancedSignature}s
	 */
	List<AdvancedSignature> processSignaturesValidation(final ValidationContext validationContext, 
			final List<AdvancedSignature> allSignatureList, boolean structuralValidation);


}
