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

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.security.Security;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Objects;
import java.util.ServiceLoader;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.enumerations.CertificateSourceType;
import eu.europa.esig.dss.enumerations.Context;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.policy.EtsiValidationPolicy;
import eu.europa.esig.dss.policy.ValidationPolicy;
import eu.europa.esig.dss.policy.ValidationPolicyFacade;
import eu.europa.esig.dss.policy.jaxb.ConstraintsParameters;
import eu.europa.esig.dss.spi.DSSSecurityProvider;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.CertificatePool;
import eu.europa.esig.dss.validation.executor.DefaultSignatureProcessExecutor;
import eu.europa.esig.dss.validation.executor.SignatureProcessExecutor;
import eu.europa.esig.dss.validation.executor.ValidationLevel;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.validation.scope.SignatureScopeFinder;

/**
 * Validate the signed document. The content of the document is determined
 * automatically. It can be: XML, CAdES(p7m), PDF or ASiC(zip).
 * SignatureScopeFinder can be set using the appropriate setter (ex.
 * setCadesSignatureScopeFinder). By default, this class will use the default
 * SignatureScopeFinder as defined by
 * eu.europa.esig.dss.validation.scope.SignatureScopeFinderFactory
 */
public abstract class SignedDocumentValidator implements DocumentValidator, ProcessExecutorProvider<SignatureProcessExecutor> {

	private static final Logger LOG = LoggerFactory.getLogger(SignedDocumentValidator.class);

	static {
		Security.addProvider(DSSSecurityProvider.getSecurityProvider());
	}

	/**
	 * This variable can hold a specific {@code SignatureProcessExecutor}
	 */
	protected SignatureProcessExecutor processExecutor = null;

	/**
	 * This is the pool of certificates used in the validation process. The
	 * pools present in the certificate verifier are merged and added to this
	 * pool.
	 */
	protected CertificatePool validationCertPool = null;

	/**
	 * The document to be validated (with the signature(s))
	 */
	protected DSSDocument document;

	/**
	 * A time to validate the document against
	 */
	private Date validationTime;

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

	/**
	 * The reference to the certificate verifier. The current DSS implementation
	 * proposes {@link eu.europa.esig.dss.validation.CommonCertificateVerifier}.
	 * This verifier encapsulates the references to different sources used in
	 * the signature validation process.
	 */
	protected CertificateVerifier certificateVerifier;

	protected final SignatureScopeFinder signatureScopeFinder;

	protected SignaturePolicyProvider signaturePolicyProvider;

	// Default configuration with the highest level
	private ValidationLevel validationLevel = ValidationLevel.ARCHIVAL_DATA;
	
	// Produces the ETSI Validation Report by default
	private boolean enableEtsiValidationReport = true;

	protected SignedDocumentValidator(SignatureScopeFinder signatureScopeFinder) {
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
		if (token == null) {
			throw new NullPointerException("Token is not defined");
		}
		if (validationCertPool == null) {
			throw new NullPointerException("Certificate pool is not instantiated");
		}
		providedSigningCertificateToken = validationCertPool.getInstance(token, CertificateSourceType.OTHER);
	}

	/**
	 * To carry out the validation process of the signature(s) some external
	 * sources of certificates and of revocation data can be needed. The
	 * certificate verifier is used to pass these values. Note that once this
	 * setter is called any change in the content of the
	 * <code>CommonTrustedCertificateSource</code> or in adjunct certificate
	 * source is not taken into account.
	 *
	 * @param certificateVerifier
	 */
	@Override
	public void setCertificateVerifier(final CertificateVerifier certificateVerifier) {
		this.certificateVerifier = certificateVerifier;
		if (validationCertPool == null) {
			validationCertPool = certificateVerifier.createValidationPool();
		}
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
	 * Allows to define a custom validation time
	 * @param validationTime {@link Date}
	 */
	@Override
	public void setValidationTime(Date validationTime) {
		this.validationTime = validationTime;
	}

	/**
	 * Returns validation time
	 * In case if the validation time is not provided, initialize the current time value from the system
	 *
	 * @return {@link Date} validation time
	 */
	protected Date getValidationTime() {
		if (validationTime == null) {
			validationTime = new Date();
		}
		return validationTime;
	}

	@Override
	public void setValidationLevel(ValidationLevel validationLevel) {
		this.validationLevel = validationLevel;
	}
	
	@Override
	public void setEnableEtsiValidationReport(boolean enableEtsiValidationReport) {
		this.enableEtsiValidationReport = enableEtsiValidationReport;
	}

	@Override
	public Reports validateDocument() {
		return validateDocument((InputStream) null);
	}

	@Override
	public Reports validateDocument(final URL validationPolicyURL) {
		if (validationPolicyURL == null) {
			return validateDocument((InputStream) null);
		}
		try {
			return validateDocument(validationPolicyURL.openStream());
		} catch (IOException e) {
			throw new DSSException(e);
		}
	}

	@Override
	public Reports validateDocument(final String policyResourcePath) {
		if (policyResourcePath == null) {
			return validateDocument((InputStream) null);
		}
		return validateDocument(getClass().getResourceAsStream(policyResourcePath));
	}

	@Override
	public Reports validateDocument(final File policyFile) {
		if ((policyFile == null) || !policyFile.exists()) {
			return validateDocument((InputStream) null);
		}
		final InputStream inputStream = DSSUtils.toByteArrayInputStream(policyFile);
		return validateDocument(inputStream);
	}

	/**
	 * Validates the document and all its signatures. The policyDataStream
	 * contains the constraint file. If null or empty the default file is used.
	 *
	 * @param policyDataStream
	 *            the {@code InputStream} with the validation policy
	 * @return the validation reports
	 */
	@Override
	public Reports validateDocument(final InputStream policyDataStream) {
		ValidationPolicy validationPolicy = null;
		try {
			validationPolicy = ValidationPolicyFacade.newFacade().getValidationPolicy(policyDataStream);
		} catch (Exception e) {
			throw new DSSException("Unable to load the policy", e);
		}
		return validateDocument(validationPolicy);
	}

	/**
	 * Validates the document and all its signatures. The
	 * {@code validationPolicyDom} contains the constraint file. If null or
	 * empty the default file is used.
	 *
	 * @param validationPolicyJaxb
	 *            the {@code ConstraintsParameters} to use in the validation process
	 * @return the validation reports
	 */
	@Override
	public Reports validateDocument(final ConstraintsParameters validationPolicyJaxb) {
		final ValidationPolicy validationPolicy = new EtsiValidationPolicy(validationPolicyJaxb);
		return validateDocument(validationPolicy);
	}

	/**
	 * Validates the document and all its signatures. The
	 * {@code validationPolicyDom} contains the constraint file. If null or
	 * empty the default file is used.
	 *
	 * @param validationPolicy
	 *            the {@code ValidationPolicy} to use in the validation process
	 * @return the validation reports
	 */
	@Override
	public Reports validateDocument(final ValidationPolicy validationPolicy) {
		LOG.info("Document validation...");
		Objects.requireNonNull(certificateVerifier, "CertificateVerifier is not defined");
		Objects.requireNonNull(document, "Document is not provided to the validator");

		ensureSignaturePolicyDetectorInitialized();

		boolean structuralValidation = isRequireStructuralValidation(validationPolicy);
		final ValidationContext validationContext = new SignatureValidationContext(validationCertPool);

		List<AdvancedSignature> allSignatureList = prepareSignatureValidationContext(validationContext);
		allSignatureList = processSignaturesValidation(validationContext, allSignatureList, structuralValidation);

		final XmlDiagnosticData diagnosticData = new DiagnosticDataBuilder().document(document).containerInfo(getContainerInfo())
				.foundSignatures(allSignatureList)
				.usedCertificates(validationContext.getProcessedCertificates()).usedRevocations(validationContext.getProcessedRevocations())
				.setDefaultDigestAlgorithm(certificateVerifier.getDefaultDigestAlgorithm())
				.includeRawCertificateTokens(certificateVerifier.isIncludeCertificateTokenValues())
				.includeRawRevocationData(certificateVerifier.isIncludeCertificateRevocationValues())
				.includeRawTimestampTokens(certificateVerifier.isIncludeTimestampTokenValues())
				.certificateSourceTypes(validationContext.getCertificateSourceTypes())
				.trustedCertificateSource(certificateVerifier.getTrustedCertSource())
				.validationDate(validationContext.getCurrentTime()).build();

		return processValidationPolicy(diagnosticData, validationPolicy);
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

	protected Reports processValidationPolicy(XmlDiagnosticData diagnosticData, ValidationPolicy validationPolicy) {
		final SignatureProcessExecutor executor = provideProcessExecutorInstance();
		executor.setValidationPolicy(validationPolicy);
		executor.setValidationLevel(validationLevel);
		executor.setDiagnosticData(diagnosticData);
		executor.setEnableEtsiValidationReport(enableEtsiValidationReport);
		final Reports reports = executor.execute();
		return reports;
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

	@Override
	public void setProcessExecutor(final SignatureProcessExecutor processExecutor) {
		this.processExecutor = processExecutor;
	}

	/**
	 * This method returns the process executor. If the instance of this class
	 * is not yet instantiated then the new instance is created.
	 *
	 * @return {@code SignatureProcessExecutor}
	 */
	public SignatureProcessExecutor provideProcessExecutorInstance() {
		if (processExecutor == null) {
			processExecutor = new DefaultSignatureProcessExecutor();
		}
		return processExecutor;
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
