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

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.TokenExtractionStrategy;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.model.x509.revocation.crl.CRL;
import eu.europa.esig.dss.model.x509.revocation.ocsp.OCSP;
import eu.europa.esig.dss.policy.EtsiValidationPolicy;
import eu.europa.esig.dss.policy.ValidationPolicy;
import eu.europa.esig.dss.policy.ValidationPolicyFacade;
import eu.europa.esig.dss.policy.jaxb.ConstraintsParameters;
import eu.europa.esig.dss.spi.DSSSecurityProvider;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.client.http.NativeHTTPDataLoader;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.spi.x509.CommonCertificateSource;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.executor.DocumentProcessExecutor;
import eu.europa.esig.dss.validation.executor.ValidationLevel;
import eu.europa.esig.dss.validation.executor.signature.DefaultSignatureProcessExecutor;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.validation.scope.SignatureScopeFinder;
import eu.europa.esig.dss.validation.timestamp.TimestampToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.security.Security;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.ServiceLoader;

/**
 * Validates a signed document. The content of the document is determined
 * automatically. It can be: XML, CAdES(p7m), PDF or ASiC(zip).
 * SignatureScopeFinder can be set using the appropriate setter (ex.
 * setCadesSignatureScopeFinder). By default, this class will use the default
 * SignatureScopeFinder as defined by
 * eu.europa.esig.dss.validation.scope.SignatureScopeFinderFactory
 */
public abstract class SignedDocumentValidator implements DocumentValidator {

	private static final Logger LOG = LoggerFactory.getLogger(SignedDocumentValidator.class);

	static {
		Security.addProvider(DSSSecurityProvider.getSecurityProvider());
	}

	/**
	 * This variable can hold a specific {@code DocumentProcessExecutor}
	 */
	protected DocumentProcessExecutor processExecutor = null;
	
	/**
	 * The document to be validated (with the signature(s) or timestamp(s))
	 */
	protected DSSDocument document;

	/**
	 * In case of a detached signature this {@code List} contains the signed
	 * documents.
	 */
	protected List<DSSDocument> detachedContents = new ArrayList<>();
	
	/**
	 * In case of an ASiC signature this {@code List} of container documents.
	 */
	protected List<DSSDocument> containerContents;
	
	/**
	 * A related {@link ManifestFile} to the provided {@code document}
	 */
	protected ManifestFile manifestFile;

	/**
	 * Certificate source to find signing certificate
	 */
	protected CertificateSource signingCertificateSource;

	/**
	 * A time to validate the document against
	 */
	private Date validationTime;

	/**
	 * The reference to the certificate verifier. The current DSS implementation
	 * proposes {@link eu.europa.esig.dss.validation.CommonCertificateVerifier}.
	 * This verifier encapsulates the references to different sources used in the
	 * signature validation process.
	 */
	protected CertificateVerifier certificateVerifier;

	/**
	 * The used token extraction strategy to define tokens representation in DiagnosticData
	 */
	private TokenExtractionStrategy tokenExtractionStrategy = TokenExtractionStrategy.NONE;

	/**
	 * The implementation to be used for identifiers generation
	 */
	private TokenIdentifierProvider identifierProvider = new OriginalIdentifierProvider();

	/**
	 * This variable allows to include the semantics for Indication / SubIndication
	 */
	private boolean includeSemantics = false;

	/**
	 * The class to extract a list of {@code SignatureScope}s from a signature
	 */
	protected final SignatureScopeFinder signatureScopeFinder;

	/**
	 * Provides methods to extract a policy content by its identifier
	 */
	private SignaturePolicyProvider signaturePolicyProvider;

	/**
	 * The expected validation level
	 *
	 * Default: ValidationLevel.ARCHIVAL_DATA (the highest level)
	 */
	private ValidationLevel validationLevel = ValidationLevel.ARCHIVAL_DATA;
	
	/**
	 * Locale to use for reports generation
	 * By default a Locale from OS is used
	 */
	private Locale locale = Locale.getDefault();

	/**
	 * Defines if the ETSI Validation report shall be produced
	 *
	 * Default: true
	 */
	private boolean enableEtsiValidationReport = true;

	/**
	 * Defines if the validation context processing shall be skipped
	 * (Disable certificate chain building, revocation data collection,...)
	 *
	 * Default: false
	 */
	protected boolean skipValidationContextExecution = false;

	/**
	 * The constructor with a null {@code signatureScopeFinder}
	 */
	protected SignedDocumentValidator() {
		this.signatureScopeFinder = null;
	}

	/**
	 * The default constructor
	 *
	 * @param signatureScopeFinder {@link SignatureScopeFinder}
	 */
	protected SignedDocumentValidator(SignatureScopeFinder signatureScopeFinder) {
		this.signatureScopeFinder = signatureScopeFinder;
	}

	/**
	 * Sets the default algorithm to use for a {@code SignatureScopeFinder}
	 *
	 * @param digestAlgorithm {@link DigestAlgorithm}
	 */
	protected void setSignedScopeFinderDefaultDigestAlgorithm(DigestAlgorithm digestAlgorithm) {
		// Null in the ASiC Container validator
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
			if (factory.isSupported(dssDocument)) {
				return factory.create(dssDocument);
			}
		}
		throw new DSSException("Document format not recognized/handled");
	}

	/**
	 * Checks if the document is supported by the current validator
	 *
	 * @param dssDocument {@link DSSDocument} to check
	 * @return TRUE if the document is supported, FALSE otherwise
	 */
	public abstract boolean isSupported(DSSDocument dssDocument);

	@Override
	@Deprecated
	public void defineSigningCertificate(final CertificateToken token) {
		Objects.requireNonNull(token, "Token is not defined");
		CertificateSource signingCertificateResolver = new CommonCertificateSource();
		signingCertificateResolver.addCertificate(token);
		setSigningCertificateSource(signingCertificateResolver);
	}

	@Override
	public void setSigningCertificateSource(CertificateSource signingCertificateSource) {
		this.signingCertificateSource = signingCertificateSource;
	}

	/**
	 * To carry out the validation process of the signature(s) some external sources
	 * of certificates and of revocation data can be needed. The certificate
	 * verifier is used to pass these values. Note that once this setter is called
	 * any change in the content of the <code>CommonTrustedCertificateSource</code>
	 * or in adjunct certificate source is not taken into account.
	 *
	 * @param certificateVerifier {@link CertificateVerifier}
	 */
	@Override
	public void setCertificateVerifier(final CertificateVerifier certificateVerifier) {
		Objects.requireNonNull(certificateVerifier);
		this.certificateVerifier = certificateVerifier;
	}

	@Override
	public void setTokenExtractionStrategy(TokenExtractionStrategy tokenExtractionStrategy) {
		Objects.requireNonNull(tokenExtractionStrategy);
		this.tokenExtractionStrategy = tokenExtractionStrategy;
	}

	@Override
	public void setTokenIdentifierProvider(TokenIdentifierProvider identifierProvider) {
		Objects.requireNonNull(identifierProvider);
		this.identifierProvider = identifierProvider;
	}

	@Override
	public void setIncludeSemantics(boolean include) {
		this.includeSemantics = include;
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
	public void setManifestFile(ManifestFile manifestFile) {
		this.manifestFile = manifestFile;
	}

	/**
	 * Returns a default digest algorithm defined for a digest calculation
	 * 
	 * @return {@link DigestAlgorithm}
	 */
	protected DigestAlgorithm getDefaultDigestAlgorithm() {
		return certificateVerifier.getDefaultDigestAlgorithm();
	}

	/**
	 * Allows to define a custom validation time
	 * 
	 * @param validationTime {@link Date}
	 */
	@Override
	public void setValidationTime(Date validationTime) {
		this.validationTime = validationTime;
	}

	/**
	 * Returns validation time In case if the validation time is not provided,
	 * initialize the current time value from the system
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
	 * Validates the document and all its signatures. The policyDataStream contains
	 * the constraint file. If null or empty the default file is used.
	 *
	 * @param policyDataStream the {@code InputStream} with the validation policy
	 * @return the validation reports
	 */
	@Override
	public Reports validateDocument(final InputStream policyDataStream) {
		ValidationPolicy validationPolicy = null;
		try {
			if (policyDataStream == null) {
				LOG.debug("No provided validation policy : use the default policy");
				validationPolicy = ValidationPolicyFacade.newFacade().getDefaultValidationPolicy();
			} else {
				validationPolicy = ValidationPolicyFacade.newFacade().getValidationPolicy(policyDataStream);
			}
		} catch (Exception e) {
			throw new DSSException("Unable to load the policy", e);
		}
		return validateDocument(validationPolicy);
	}

	/**
	 * Validates the document and all its signatures. The
	 * {@code validationPolicyDom} contains the constraint file. If null or empty
	 * the default file is used.
	 *
	 * @param validationPolicyJaxb the {@code ConstraintsParameters} to use in the
	 *                             validation process
	 * @return the validation reports
	 */
	@Override
	public Reports validateDocument(final ConstraintsParameters validationPolicyJaxb) {
		final ValidationPolicy validationPolicy = new EtsiValidationPolicy(validationPolicyJaxb);
		return validateDocument(validationPolicy);
	}

	/**
	 * Validates the document and all its signatures. The
	 * {@code validationPolicyDom} contains the constraint file. If null or empty
	 * the default file is used.
	 *
	 * @param validationPolicy the {@code ValidationPolicy} to use in the validation
	 *                         process
	 * @return the validation reports
	 */
	@Override
	public Reports validateDocument(final ValidationPolicy validationPolicy) {
		LOG.info("Document validation...");
		assertConfigurationValid();

		final XmlDiagnosticData diagnosticData = prepareDiagnosticDataBuilder().build();

		return processValidationPolicy(diagnosticData, validationPolicy);
	}

	/**
	 * Checks if the Validator configuration is valid
	 */
	protected void assertConfigurationValid() {
		Objects.requireNonNull(certificateVerifier, "CertificateVerifier is not defined");
		Objects.requireNonNull(document, "Document is not provided to the validator");
	}

	/**
	 * Creates a {@code DiagnosticDataBuilder}
	 * 
	 * @return {@link DiagnosticDataBuilder}
	 */
	protected DiagnosticDataBuilder prepareDiagnosticDataBuilder() {
		
		List<AdvancedSignature> allSignatures = getAllSignatures();
        List<TimestampToken> detachedTimestamps = getDetachedTimestamps();

		ValidationContext validationContext = prepareValidationContext(allSignatures, detachedTimestamps);

		if (!skipValidationContextExecution) {
			validateContext(validationContext);
		}
		
		ListRevocationSource<CRL> listCRLSource = mergeCRLSources(allSignatures, detachedTimestamps);
		ListRevocationSource<OCSP> listOCSPSource = mergeOCSPSources(allSignatures, detachedTimestamps);
		return createDiagnosticDataBuilder(validationContext, allSignatures, listCRLSource, listOCSPSource);
	}

	/**
	 * Initializes and fills {@code ValidationContext} with necessary data sources
	 * 
	 * @param <T> {@link AdvancedSignature} implementation
	 * @param signatures a collection of {@link AdvancedSignature}s
	 * @param detachedTimestamps a collection of detached {@link TimestampToken}s
	 * @return {@link ValidationContext}
	 */
	protected <T extends AdvancedSignature> ValidationContext prepareValidationContext(
			final Collection<T> signatures, final Collection<TimestampToken> detachedTimestamps) {
		ValidationContext validationContext = new SignatureValidationContext();
		prepareSignatureValidationContext(validationContext, signatures);
		prepareDetachedTimestampValidationContext(validationContext, detachedTimestamps);
		return validationContext;
	}
	
	/**
	 * Initializes a relevant {@code DiagnosticDataBuilder} for the given
	 * implementation
	 * 
	 * @return {@link SignedDocumentDiagnosticDataBuilder}
	 */
	protected SignedDocumentDiagnosticDataBuilder initializeDiagnosticDataBuilder() {
		return new SignedDocumentDiagnosticDataBuilder(); // by default
	}

	@Override
	public <T extends AdvancedSignature> ValidationDataContainer getValidationData(Collection<T> signatures) {
		return getValidationData(signatures, Collections.emptyList());
	}

	@Override
	public <T extends AdvancedSignature> ValidationDataContainer getValidationData(Collection<T> signatures,
																				   Collection<TimestampToken> detachedTimestamps) {
		if (Utils.isCollectionEmpty(signatures) && Utils.isCollectionEmpty(detachedTimestamps)) {
			throw new DSSException("At least one signature or a timestamp shall be provided to extract the validation data!");
		}

		ValidationContext validationContext = prepareValidationContext(signatures, detachedTimestamps);
		validateContext(validationContext);

		assertSignaturesValid(signatures, validationContext);

		ValidationDataContainer validationDataContainer = new ValidationDataContainer();
		for (AdvancedSignature signature : signatures) {
			ValidationData signatureValidationData = validationContext.getValidationData(signature);
			validationDataContainer.addValidationData(signature, signatureValidationData);
			for (TimestampToken timestampToken : signature.getAllTimestamps()) {
				ValidationData timestampValidationData = validationContext.getValidationData(timestampToken);
				validationDataContainer.addValidationData(timestampToken, timestampValidationData);
			}
			for (AdvancedSignature counterSignature : signature.getCounterSignatures()) {
				ValidationData counterSignatureValidationData = validationContext.getValidationData(counterSignature);
				validationDataContainer.addValidationData(counterSignature, counterSignatureValidationData);
			}
		}
		for (TimestampToken detachedTimestamp : detachedTimestamps) {
			ValidationData timestampValidationData = validationContext.getValidationData(detachedTimestamp);
			validationDataContainer.addValidationData(detachedTimestamp, timestampValidationData);
		}

		return validationDataContainer;
	}

	private <T extends AdvancedSignature> void assertSignaturesValid(Collection<T> signatures,
																	 ValidationContext validationContext) {

		validationContext.checkAllTimestampsValid();
		validationContext.checkAllRequiredRevocationDataPresent();
		validationContext.checkAllPOECoveredByRevocationData();
		validationContext.checkAllCertificatesValid();

		for (final AdvancedSignature signature : signatures) {
			CertificateToken signingCertificateToken = signature.getSigningCertificateToken();
			if (signingCertificateToken != null) {
				validationContext.checkAtLeastOneRevocationDataPresentAfterBestSignatureTime(signingCertificateToken);
				validationContext.checkSignatureNotExpired(signingCertificateToken);
			}
		}
	}

	/**
	 * Creates and fills the {@code DiagnosticDataBuilder} with a relevant data
	 * 
	 * @param validationContext {@link ValidationContext} used for the validation
	 * @param signatures        a list of {@link AdvancedSignature}s to be validated
	 * @param listCRLSource     {@link ListRevocationSource} used for CRL collection
	 * @param listOCSPSource    {@link ListRevocationSource} used for OCSP
	 *                          collection
	 * @return filled {@link DiagnosticDataBuilder}
	 */
	protected DiagnosticDataBuilder createDiagnosticDataBuilder(
			final ValidationContext validationContext, List<AdvancedSignature> signatures,
			final ListRevocationSource<CRL> listCRLSource, final ListRevocationSource<OCSP> listOCSPSource) {
		return initializeDiagnosticDataBuilder().document(document)
				.foundSignatures(signatures)
				.usedTimestamps(validationContext.getProcessedTimestamps())
				.completeCRLSource(listCRLSource).completeOCSPSource(listOCSPSource)
				.signaturePolicyProvider(getSignaturePolicyProvider())
				.usedCertificates(validationContext.getProcessedCertificates())
				.usedRevocations(validationContext.getProcessedRevocations())
				.defaultDigestAlgorithm(certificateVerifier.getDefaultDigestAlgorithm())
				.tokenExtractionStrategy(tokenExtractionStrategy)
				.tokenIdentifierProvider(identifierProvider)
				.certificateSourceTypes(validationContext.getCertificateSourceTypes())
				.trustedCertificateSources(certificateVerifier.getTrustedCertSources())
				.validationDate(getValidationTime());
	}

	/**
	 * For all signatures to be validated this method merges the CRL sources.
	 *
	 * @param allSignatureList   {@code Collection} of {@code AdvancedSignature}s to
	 *                           validate including the counter-signatures
	 * @param detachedTimestamps   {@code Collection} of {@code TimestampToken}s
	 *                           detached to a validating file
	 * @return merged CRL Source
	 */
	protected ListRevocationSource<CRL> mergeCRLSources(final Collection<AdvancedSignature> allSignatureList, Collection<TimestampToken> detachedTimestamps) {
		ListRevocationSource<CRL> allCrlSource = new ListRevocationSource<>();
		if (Utils.isCollectionNotEmpty(allSignatureList)) {
			for (final AdvancedSignature signature : allSignatureList) {
				allCrlSource.addAll(signature.getCompleteCRLSource());
			}
		}
		if (Utils.isCollectionNotEmpty(detachedTimestamps)) {
			for (TimestampToken timestampToken : detachedTimestamps) {
				allCrlSource.add(timestampToken.getCRLSource());
			}
		}
		return allCrlSource;
	}

	/**
	 * For all signatures to be validated this method merges the OCSP sources.
	 *
	 * @param allSignatureList   {@code Collection} of {@code AdvancedSignature}s to
	 *                           validate including the counter-signatures
	 * @param detachedTimestamps   {@code Collection} of {@code TimestampToken}s
	 *                           detached to a validating file
	 * @return merged OCSP Source
	 */
	protected ListRevocationSource<OCSP> mergeOCSPSources(final Collection<AdvancedSignature> allSignatureList, Collection<TimestampToken> detachedTimestamps) {
		ListRevocationSource<OCSP> allOcspSource = new ListRevocationSource<>();
		if (Utils.isCollectionNotEmpty(allSignatureList)) {
			for (final AdvancedSignature signature : allSignatureList) {
				allOcspSource.addAll(signature.getCompleteOCSPSource());
			}
		}
		if (Utils.isCollectionNotEmpty(detachedTimestamps)) {
			for (TimestampToken timestampToken : detachedTimestamps) {
				allOcspSource.add(timestampToken.getOCSPSource());
			}
		}
		return allOcspSource;
	}

	/**
	 * Prepares the {@code validationContext} for signature validation process
	 *
	 * @param <T>
	 *                          {@link AdvancedSignature} implementation
	 * @param validationContext
	 *                          {@link ValidationContext}
	 * @param allSignatures
	 *                          a collection of all {@link AdvancedSignature}s to be
	 *                          validated
	 */
	protected <T extends AdvancedSignature> void prepareSignatureValidationContext(
			final ValidationContext validationContext, final Collection<T> allSignatures) {
		prepareSignatureForVerification(validationContext, allSignatures);
		processSignaturesValidation(allSignatures);
	}

	/**
	 * This method prepares a {@code SignatureValidationContext} for signatures validation
	 *
	 * @param <T>
	 *                          {@link AdvancedSignature} implementation
	 * @param allSignatureList  {@code Collection} of {@code AdvancedSignature}s to
	 *                          validate including the countersignatures
	 * @param validationContext {@code ValidationContext} is the implementation of
	 *                          the validators for: certificates, timestamps and
	 *                          revocation data.
	 */
	protected <T extends AdvancedSignature> void prepareSignatureForVerification(
			final ValidationContext validationContext, final Collection<T> allSignatureList) {
		for (final AdvancedSignature signature : allSignatureList) {
			validationContext.addSignatureForVerification(signature);
		}
	}

	/**
	 * Prepares the {@code validationContext} for a timestamp validation process
	 *
	 * @param validationContext
	 *                          {@link ValidationContext}
	 * @param timestamps
	 *                          a collection of detached timestamps
	 */
	protected void prepareDetachedTimestampValidationContext(final ValidationContext validationContext, Collection<TimestampToken> timestamps) {
		for (TimestampToken timestampToken : timestamps) {
			validationContext.addTimestampTokenForVerification(timestampToken);
		}
	}

	/**
	 * Process the validation
	 * 
	 * @param validationContext {@link ValidationContext} to process
	 */
	protected void validateContext(final ValidationContext validationContext) {
		validationContext.initialize(certificateVerifier);
		validationContext.validate();
	}
	
	@Override
	public void setSignaturePolicyProvider(SignaturePolicyProvider signaturePolicyProvider) {
		this.signaturePolicyProvider = signaturePolicyProvider;
	}

	/**
	 * Returns a signaturePolicyProvider If not defined, returns a default provider
	 * 
	 * @return {@link SignaturePolicyProvider}
	 */
	protected SignaturePolicyProvider getSignaturePolicyProvider() {
		if (signaturePolicyProvider == null) {
			LOG.info("Default SignaturePolicyProvider instantiated with NativeHTTPDataLoader.");
			signaturePolicyProvider = new SignaturePolicyProvider();
			signaturePolicyProvider.setDataLoader(new NativeHTTPDataLoader());
		}
		return signaturePolicyProvider;
	}
	
	@Override
	public void setProcessExecutor(final DocumentProcessExecutor processExecutor) {
		this.processExecutor = processExecutor;
	}
	
	/**
	 * This method returns the process executor. If the instance of this class is
	 * not yet instantiated then the new instance is created.
	 *
	 * @return {@code SignatureProcessExecutor}
	 */
	protected DocumentProcessExecutor provideProcessExecutorInstance() {
		if (processExecutor == null) {
			processExecutor = getDefaultProcessExecutor();
		}
		return processExecutor;
	}

	@Override
	public DocumentProcessExecutor getDefaultProcessExecutor() {
		return new DefaultSignatureProcessExecutor();
	}

	/**
	 * Executes the validation regarding to the given {@code validationPolicy}
	 * 
	 * @param diagnosticData   {@link DiagnosticData} contained a data to be
	 *                         validated
	 * @param validationPolicy {@link ValidationPolicy}
	 * @return validation {@link Reports}
	 */
	protected final Reports processValidationPolicy(XmlDiagnosticData diagnosticData, ValidationPolicy validationPolicy) {
		final DocumentProcessExecutor executor = provideProcessExecutorInstance();
		executor.setValidationPolicy(validationPolicy);
		executor.setValidationLevel(validationLevel);
		executor.setDiagnosticData(diagnosticData);
		executor.setIncludeSemantics(includeSemantics);
		executor.setEnableEtsiValidationReport(enableEtsiValidationReport);
		executor.setLocale(locale);
		executor.setCurrentTime(getValidationTime());
		return executor.execute();
	}

	/**
	 * Returns a list of all signatures from the validating document
	 *
	 * @return a list of {@link AdvancedSignature}s
	 */
	protected List<AdvancedSignature> getAllSignatures() {

		setSignedScopeFinderDefaultDigestAlgorithm(certificateVerifier.getDefaultDigestAlgorithm());

		final List<AdvancedSignature> allSignatureList = new ArrayList<>();
		for (final AdvancedSignature signature : getSignatures()) {
			allSignatureList.add(signature);
			appendCounterSignatures(allSignatureList, signature);
		}
		
		// Signature Scope must be processed before in order to properly initialize content timestamps
		// TODO change this
		findSignatureScopes(allSignatureList);
		
		return allSignatureList;
	}

	/**
	 * The util method to link counter signatures with the related master signatures
	 *
	 * @param allSignatureList a list of {@link AdvancedSignature}s
	 * @param signature current {@link AdvancedSignature}
	 */
	protected void appendCounterSignatures(final List<AdvancedSignature> allSignatureList,
										   final AdvancedSignature signature) {
		for (AdvancedSignature counterSignature : signature.getCounterSignatures()) {
			counterSignature.prepareOfflineCertificateVerifier(certificateVerifier);
			allSignatureList.add(counterSignature);
			
			appendCounterSignatures(allSignatureList, counterSignature);
		}
	}
	
	@Override
	public List<AdvancedSignature> getSignatures() {
		// delegated in CommonSignatureValidator
		return Collections.emptyList();
	}

	@Override
	public List<TimestampToken> getDetachedTimestamps() {
		// not implemented by default
		// requires an implementation of {@code SignatureValidator}
		return Collections.emptyList();
	}

	@Override
	public <T extends AdvancedSignature>  void processSignaturesValidation(Collection<T> allSignatureList) {
		for (final AdvancedSignature signature : allSignatureList) {
			signature.checkSignatureIntegrity();
		}
	}

	/**
	 * Finds and assigns SignatureScopes for a list of signatures
	 * 
	 * @param allSignatures
	 *                      a list of {@link AdvancedSignature}s to get a
	 *                      SignatureScope list
	 */
	@Override
	public <T extends AdvancedSignature> void findSignatureScopes(Collection<T> allSignatures) {
		for (final AdvancedSignature signature : allSignatures) {
			signature.findSignatureScope(signatureScopeFinder);
		}
	}

	/**
	 * Sets if the validation context execution shall be skipped
	 * (skips certificate chain building, revocation requests, ...)
	 *
	 * @param skipValidationContextExecution if the context validation shall be skipped
	 */
	public void setSkipValidationContextExecution(boolean skipValidationContextExecution) {
		this.skipValidationContextExecution = skipValidationContextExecution;
	}

	/**
	 * Sets Locale for report messages generation
	 *
	 * @param locale {@link Locale}
	 */
	public void setLocale(Locale locale) {
		this.locale = locale;
	}

	@Override
	public List<DSSDocument> getOriginalDocuments(String signatureId) {
		AdvancedSignature advancedSignature = getSignatureById(signatureId);
		if (advancedSignature != null) {
			return getOriginalDocuments(advancedSignature);
		}
		return Collections.emptyList();
	}

	/**
	 * Returns the signature with the given id. Processes custom {@code TokenIdentifierProvider} and counter signatures
	 *
	 * @param signatureId {@link String} id of a signature to be extracted
	 * @return {@link AdvancedSignature} with the given id if found, NULL otherwise
	 */
	public AdvancedSignature getSignatureById(String signatureId) {
		Objects.requireNonNull(signatureId, "Signature Id cannot be null!");
		for (AdvancedSignature advancedSignature : getSignatures()) {
			AdvancedSignature signature = findSignatureRecursively(advancedSignature, signatureId);
			if (signature != null) {
				return signature;
			}
		}
		return null;
	}

	private AdvancedSignature findSignatureRecursively(AdvancedSignature signature, String signatureId) {
		if (doesIdMatch(signature, signatureId)) {
			return signature;
		}
		for (AdvancedSignature counterSignature : signature.getCounterSignatures()) {
			AdvancedSignature advancedSignature = findSignatureRecursively(counterSignature, signatureId);
			if (advancedSignature != null) {
				return advancedSignature;
			}
		}
		return null;
	}

	private boolean doesIdMatch(AdvancedSignature signature, String signatureId) {
		return signatureId.equals(signature.getId()) || signatureId.equals(signature.getDAIdentifier()) ||
				signatureId.equals(identifierProvider.getIdAsString(signature));
	}

	/**
	 * Gets digest of a document
	 *
	 * @param document {@link DSSDocument}
	 * @return {@link Digest}
	 */
	protected Digest getDigest(DSSDocument document) {
		return new Digest(getDefaultDigestAlgorithm(), Utils.fromBase64(document.getDigest(getDefaultDigestAlgorithm())));
	}

}
