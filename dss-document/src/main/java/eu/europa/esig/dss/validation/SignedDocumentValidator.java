/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * 
 * This file is part of the "DSS - Digital Signature Services" project.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.validation;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.ServiceLoader;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.enumerations.CertificateSourceType;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.validation.scope.SignatureScopeFinder;

/**
 * Validates a signed document. The content of the document is determined
 * automatically. It can be: XML, CAdES(p7m), PDF or ASiC(zip).
 * SignatureScopeFinder can be set using the appropriate setter (ex.
 * setCadesSignatureScopeFinder). By default, this class will use the default
 * SignatureScopeFinder as defined by
 * eu.europa.esig.dss.validation.scope.SignatureScopeFinderFactory
 */
public abstract class SignedDocumentValidator extends AbstractDocumentValidator implements SignatureValidator {

	private static final Logger LOG = LoggerFactory.getLogger(SignedDocumentValidator.class);

	/**
	 * In case of a detached signature this {@code List} contains the signed
	 * documents.
	 */
	protected List<DSSDocument> detachedContents = new ArrayList<DSSDocument>();

	/**
	 * In case of an ASiC signature this {@code List} of container documents.
	 */
	protected List<DSSDocument> containerContents;
	
	/**
	 * List of all found {@link ManifestFile}s
	 */
	protected List<ManifestFile> manifestFiles;

	protected CertificateToken providedSigningCertificateToken = null;

	private SignaturePolicyProvider signaturePolicyProvider;

	protected final SignatureScopeFinder<AdvancedSignature> scopeFinder;

	protected SignedDocumentValidator(SignatureScopeFinder scopeFinder) {
		this.scopeFinder = scopeFinder;
	}
	
	private void setSignedScopeFinderDefaultDigestAlgorithm(DigestAlgorithm digestAlgorithm) {
		Objects.requireNonNull(scopeFinder, "ScopeFinder is null");
		scopeFinder.setDefaultDigestAlgorithm(digestAlgorithm);
	}

	/**
	 * This method guesses the document format and returns an appropriate
	 * document validator.
	 *
	 * @param dssDocument
	 *            The instance of {@code DSSDocument} to validate
	 * @return returns the specific instance of SignedDocumentValidator in terms
	 *         of the document type
	 */
	public static SignedDocumentValidator fromDocument(final DSSDocument dssDocument) {
		Objects.requireNonNull(dssDocument, "DSSDocument is null");
		ServiceLoader<DocumentValidatorFactory> serviceLoaders = ServiceLoader.load(DocumentValidatorFactory.class);
		for (DocumentValidatorFactory factory : serviceLoaders) {
			try {
				if (factory.isSupported(dssDocument)) {
					return factory.create(dssDocument);
				}
			} catch (Exception e) {
				LOG.error(String.format("Unable to create a DocumentValidator with the factory '%s'", factory.getClass().getSimpleName()), e);
			}
		}
		throw new DSSException("Document format not recognized/handled");
	}

	public abstract boolean isSupported(DSSDocument dssDocument);

	@Override
	public void defineSigningCertificate(final CertificateToken token) {
		Objects.requireNonNull(token, "Token is not defined");
		Objects.requireNonNull(validationCertPool, "Certificate pool is not instantiated");
		providedSigningCertificateToken = validationCertPool.getInstance(token, CertificateSourceType.OTHER);
	}

	@Override
	public void setDetachedContents(final List<DSSDocument> detachedContents) {
		this.detachedContents = detachedContents;
	}
	
	@Override
	public void setContainerContents(List<DSSDocument> containerContents) {
		this.containerContents = containerContents;
	}
	
	@Override
	public void setManifestFiles(List<ManifestFile> manifestFiles) {
		this.manifestFiles = manifestFiles;
	}

	/**
	 * This method allows to retrieve the container information (ASiC Container)
	 * 
	 * @return the container information
	 */
	protected ContainerInfo getContainerInfo() {
		// not implemented by default
		// see ASiC Container Validator
		return null;
	}

	@Override
	public void setSignaturePolicyProvider(SignaturePolicyProvider signaturePolicyProvider) {
		this.signaturePolicyProvider = signaturePolicyProvider;
	}

	/**
	 * Returns a signaturePolicyProvider
	 * If not defined, returns a default provider
	 * 
	 * @return {@link SignaturePolicyProvider}
	 */
	protected SignaturePolicyProvider getSignaturePolicyProvider() {
		if (signaturePolicyProvider == null) {
			signaturePolicyProvider = new SignaturePolicyProvider();
			signaturePolicyProvider.setDataLoader(certificateVerifier.getDataLoader());
		}
		return signaturePolicyProvider;
	}
	
	@Override
	protected DiagnosticDataBuilder prepareDiagnosticDataBuilder(final ValidationContext validationContext) {
		return super.prepareDiagnosticDataBuilder(validationContext).containerInfo(getContainerInfo());
	}
	
	@Override
	protected void prepareSignatureValidationContext(final ValidationContext validationContext,
			final List<AdvancedSignature> allSignatureList) {		
		prepareCertificatesAndTimestamps(validationContext, allSignatureList);
		processSignaturesValidation(validationContext, allSignatureList);
	}

	protected void processSignaturesValidation(final ValidationContext validationContext, 
			List<AdvancedSignature> allSignatureList) {
		for (final AdvancedSignature signature : allSignatureList) {
			signature.checkSigningCertificate();
			signature.checkSignatureIntegrity();
			signature.validateStructure();
			signature.checkSignaturePolicy(getSignaturePolicyProvider());
		}
	}

	@Override
	protected List<AdvancedSignature> getAllSignatures() {
		
		final List<AdvancedSignature> allSignatureList = new ArrayList<AdvancedSignature>();
		for (final AdvancedSignature signature : getSignatures()) {
			allSignatureList.add(signature);
			allSignatureList.addAll(signature.getCounterSignatures());			
		}
		
		// Signature Scope must be processed before in order to properly initialize content timestamps
		findSignatureScopes(allSignatureList);
		
		return allSignatureList;
	}
	
	/**
	 * Finds and assigns SignatureScopes for a list of signatures
	 * 
	 * @param allSignatures a list of {@link AdvancedSignature}s to get a SignatureScope list
	 */
	public void findSignatureScopes(List<AdvancedSignature> allSignatures) {
		setSignedScopeFinderDefaultDigestAlgorithm(getDefaultDigestAlgorithm());
		for (final AdvancedSignature signature : allSignatures) {
			signature.findSignatureScope(scopeFinder);
		}
	}

	/**
	 * @param allSignatureList
	 *            {@code List} of {@code AdvancedSignature}s to validate
	 *            including the countersignatures
	 * @param validationContext
	 *            {@code ValidationContext} is the implementation of the
	 *            validators for: certificates, timestamps and revocation data.
	 */
	protected void prepareCertificatesAndTimestamps(final ValidationContext validationContext, final List<AdvancedSignature> allSignatureList) {
		if (providedSigningCertificateToken != null) {
			validationContext.addCertificateTokenForVerification(providedSigningCertificateToken);
		}
		for (final AdvancedSignature signature : allSignatureList) {
			final List<CertificateToken> candidates = signature.getCertificates();
			for (final CertificateToken certificateToken : candidates) {
				validationContext.addCertificateTokenForVerification(certificateToken);
			}
			// Add certificate from CertPool,... if not embedded in the signature
			CandidatesForSigningCertificate candidatesForSigningCertificate = signature.getCandidatesForSigningCertificate();
			if (candidatesForSigningCertificate != null) {
				CertificateValidity certificateValidity = candidatesForSigningCertificate.getTheCertificateValidity();
				if (certificateValidity != null) {
					CertificateToken signingCertificateCandidateToken = certificateValidity.getCertificateToken();
					if (signingCertificateCandidateToken != null) {
						validationContext.addCertificateTokenForVerification(signingCertificateCandidateToken);
					}
				}
			}
			signature.prepareTimestamps(validationContext);
		}
	}

}
