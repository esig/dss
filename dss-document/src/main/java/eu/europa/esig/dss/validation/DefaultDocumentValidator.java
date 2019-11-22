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

import java.security.Security;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.ServiceLoader;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.enumerations.CertificateSourceType;
import eu.europa.esig.dss.enumerations.Context;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.policy.ValidationPolicy;
import eu.europa.esig.dss.spi.DSSSecurityProvider;
import eu.europa.esig.dss.validation.executor.SignatureProcessExecutor;
import eu.europa.esig.dss.validation.executor.signature.DefaultSignatureProcessExecutor;
import eu.europa.esig.dss.validation.scope.SignatureScopeFinder;

/**
 * Validates a signed/timestamped document. The content of the document is determined
 * automatically. It can be: XML, CAdES(p7m), PDF or ASiC(zip).
 * SignatureScopeFinder can be set using the appropriate setter (ex.
 * setCadesSignatureScopeFinder). By default, this class will use the default
 * SignatureScopeFinder as defined by
 * eu.europa.esig.dss.validation.scope.SignatureScopeFinderFactory
 */
public abstract class DefaultDocumentValidator extends AbstractDocumentValidator implements SignatureValidator {

	private static final Logger LOG = LoggerFactory.getLogger(DefaultDocumentValidator.class);

	static {
		Security.addProvider(DSSSecurityProvider.getSecurityProvider());
	}

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

	protected final SignatureScopeFinder signatureScopeFinder;

	protected SignaturePolicyProvider signaturePolicyProvider;

	protected DefaultDocumentValidator(SignatureScopeFinder signatureScopeFinder) {
		this.signatureScopeFinder = signatureScopeFinder;
	}
	
	private void setSignedScopeFinderDefaultDigestAlgorithm(DigestAlgorithm digestAlgorithm) {
		if (signatureScopeFinder != null) {
			signatureScopeFinder.setDefaultDigestAlgorithm(digestAlgorithm);
		}
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
	public static DefaultDocumentValidator fromDocument(final DSSDocument dssDocument) {
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
		if (token == null) {
			throw new NullPointerException("Token is not defined");
		}
		if (validationCertPool == null) {
			throw new NullPointerException("Certificate pool is not instantiated");
		}
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
	
	protected DiagnosticDataBuilder prepareDiagnosticDataBuilder(final ValidationContext validationContext, final ValidationPolicy validationPolicy) {
		ensureSignaturePolicyDetectorInitialized();

		boolean structuralValidation = isRequireStructuralValidation(validationPolicy);

		List<AdvancedSignature> allSignatureList = prepareSignatureValidationContext(validationContext);
		allSignatureList = processSignaturesValidation(validationContext, allSignatureList, structuralValidation);
		
		return super.prepareDiagnosticDataBuilder(validationContext, validationPolicy)
				.foundSignatures(allSignatureList).containerInfo(getContainerInfo());
	}
	
	@Override
	public List<AdvancedSignature> prepareSignatureValidationContext(final ValidationContext validationContext) {
		final List<AdvancedSignature> allSignatureList = getAllSignatures();
		// The list of all signing certificates is created to allow a parallel
		// validation.
		
		// Signature Scope must be processed before in order to properly initialize content timestamps
		setSignedScopeFinderDefaultDigestAlgorithm(certificateVerifier.getDefaultDigestAlgorithm());
		for (final AdvancedSignature signature : allSignatureList) {
			if (signatureScopeFinder != null) {
				signature.findSignatureScope(signatureScopeFinder);
			}
		}
		prepareCertificatesAndTimestamps(allSignatureList, validationContext);
		
		return allSignatureList;
	}

	@Override
	public List<AdvancedSignature> processSignaturesValidation(final ValidationContext validationContext, 
			final List<AdvancedSignature> allSignatureList, boolean structuralValidation) {
		
		final ListCRLSource signatureCRLSource = getSignatureCrlSource(allSignatureList);
		certificateVerifier.setSignatureCRLSource(signatureCRLSource);

		final ListOCSPSource signatureOCSPSource = getSignatureOcspSource(allSignatureList);
		certificateVerifier.setSignatureOCSPSource(signatureOCSPSource);

		validationContext.setCurrentTime(provideProcessExecutorInstance().getCurrentTime());
		validationContext.initialize(certificateVerifier);
		validationContext.validate();

		for (final AdvancedSignature signature : allSignatureList) {
			signature.checkSigningCertificate();
			signature.checkSignatureIntegrity();
			if (structuralValidation) {
				signature.validateStructure();
			}
			signature.checkSignaturePolicy(signaturePolicyProvider);

			signature.populateCRLTokenLists(signatureCRLSource);
			signature.populateOCSPTokenLists(signatureOCSPSource);
		}
		
		return allSignatureList;
	}

	/**
	 * This method allows to retrieve the container information (ASiC Container)
	 * 
	 * @return the container information
	 */
	protected ContainerInfo getContainerInfo() {
		return null;
	}

	@Override
	public void setSignaturePolicyProvider(SignaturePolicyProvider signaturePolicyProvider) {
		this.signaturePolicyProvider = signaturePolicyProvider;
	}

	protected void ensureSignaturePolicyDetectorInitialized() {
		if (signaturePolicyProvider == null) {
			signaturePolicyProvider = new SignaturePolicyProvider();
			signaturePolicyProvider.setDataLoader(certificateVerifier.getDataLoader());
		}
	}

	/**
	 * This method returns the process executor. If the instance of this class
	 * is not yet instantiated then the new instance is created.
	 *
	 * @return {@code SignatureProcessExecutor}
	 */
	public SignatureProcessExecutor provideProcessExecutorInstance() {
		if (processExecutor == null) {
			processExecutor = getDefaultProcessExecutor();
		}
		return processExecutor;
	}
	
	protected SignatureProcessExecutor getDefaultProcessExecutor() {
		return new DefaultSignatureProcessExecutor();
	}

	/**
	 * This method returns the list of all signatures including the
	 * countersignatures.
	 *
	 * @return {@code List} of {@code AdvancedSignature} to validate
	 */
	private List<AdvancedSignature> getAllSignatures() {
		final List<AdvancedSignature> allSignatureList = new ArrayList<AdvancedSignature>();
		List<AdvancedSignature> signatureList = getSignatures();
		for (final AdvancedSignature signature : signatureList) {
			allSignatureList.add(signature);
			allSignatureList.addAll(signature.getCounterSignatures());
		}
		return allSignatureList;
	}

	/**
	 * For all signatures to be validated this method merges the CRL sources.
	 *
	 * @param allSignatureList
	 *            {@code List} of {@code AdvancedSignature}s to validate
	 *            including the countersignatures
	 * @return {@code ListCRLSource}
	 */
	private ListCRLSource getSignatureCrlSource(final List<AdvancedSignature> allSignatureList) {
		final ListCRLSource signatureCrlSource = new ListCRLSource();
		for (final AdvancedSignature signature : allSignatureList) {
			signatureCrlSource.addAll(signature.getCompleteCRLSource());
		}
		return signatureCrlSource;
	}

	/**
	 * For all signatures to be validated this method merges the OCSP sources.
	 *
	 * @param allSignatureList
	 *            {@code List} of {@code AdvancedSignature}s to validate
	 *            including the countersignatures
	 * @return {@code ListOCSPSource}
	 */
	private ListOCSPSource getSignatureOcspSource(final List<AdvancedSignature> allSignatureList) {
		final ListOCSPSource signatureOcspSource = new ListOCSPSource();
		for (final AdvancedSignature signature : allSignatureList) {
			signatureOcspSource.addAll(signature.getCompleteOCSPSource());
		}
		return signatureOcspSource;
	}

	/**
	 * @param allSignatureList
	 *            {@code List} of {@code AdvancedSignature}s to validate
	 *            including the countersignatures
	 * @param validationContext
	 *            {@code ValidationContext} is the implementation of the
	 *            validators for: certificates, timestamps and revocation data.
	 */
	private void prepareCertificatesAndTimestamps(final List<AdvancedSignature> allSignatureList, final ValidationContext validationContext) {
		if (providedSigningCertificateToken != null) {
			validationContext.addCertificateTokenForVerification(providedSigningCertificateToken);
		}
		for (final AdvancedSignature signature : allSignatureList) {
			final List<CertificateToken> candidates = signature.getCertificates();
			for (final CertificateToken certificateToken : candidates) {
				validationContext.addCertificateTokenForVerification(certificateToken);
			}
			signature.prepareTimestamps(validationContext);
		}
	}

	private boolean isRequireStructuralValidation(ValidationPolicy validationPolicy) {
		return ((validationPolicy != null) && (validationPolicy.getStructuralValidationConstraint(Context.SIGNATURE) != null));
	}

}
