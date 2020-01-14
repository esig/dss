package eu.europa.esig.dss.validation;

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
import java.util.Objects;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.policy.EtsiValidationPolicy;
import eu.europa.esig.dss.policy.ValidationPolicy;
import eu.europa.esig.dss.policy.ValidationPolicyFacade;
import eu.europa.esig.dss.policy.jaxb.ConstraintsParameters;
import eu.europa.esig.dss.spi.DSSSecurityProvider;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.CertificatePool;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.executor.DocumentProcessExecutor;
import eu.europa.esig.dss.validation.executor.ValidationLevel;
import eu.europa.esig.dss.validation.executor.signature.DefaultSignatureProcessExecutor;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.validation.scope.SignatureScope;
import eu.europa.esig.dss.validation.timestamp.TimestampToken;
import eu.europa.esig.dss.validation.timestamp.TimestampedReference;

public abstract class AbstractDocumentValidator implements DocumentValidator {

	private static final Logger LOG = LoggerFactory.getLogger(AbstractDocumentValidator.class);

	static {
		Security.addProvider(DSSSecurityProvider.getSecurityProvider());
	}

	/**
	 * The document to be validated (with the signature(s) or timestamp(s))
	 */
	protected DSSDocument document;
	
	/**
	 * A time to validate the document against
	 */
	private Date validationTime;

	/**
	 * The reference to the certificate verifier. The current DSS implementation
	 * proposes {@link eu.europa.esig.dss.validation.CommonCertificateVerifier}.
	 * This verifier encapsulates the references to different sources used in
	 * the signature validation process.
	 */
	protected CertificateVerifier certificateVerifier;

	/**
	 * This variable can hold a specific {@code DocumentProcessExecutor}
	 */
	protected DocumentProcessExecutor processExecutor = null;

	/**
	 * This is the pool of certificates used in the validation process. The
	 * pools present in the certificate verifier are merged and added to this
	 * pool.
	 */
	protected CertificatePool validationCertPool = null;

	// Default configuration with the highest level
	private ValidationLevel validationLevel = ValidationLevel.ARCHIVAL_DATA;
	
	// Produces the ETSI Validation Report by default
	private boolean enableEtsiValidationReport = true;

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
	public void setProcessExecutor(final DocumentProcessExecutor processExecutor) {
		this.processExecutor = processExecutor;
	}

	/**
	 * This method returns the process executor. If the instance of this class
	 * is not yet instantiated then the new instance is created.
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
	 * Returns a default digest algorithm defined for a digest calculation
	 * 
	 * @return {@link DigestAlgorithm}
	 */
	protected DigestAlgorithm getDefaultDigestAlgorithm() {
		return certificateVerifier.getDefaultDigestAlgorithm();
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
		assertConfigurationValid();

		final ValidationContext validationContext = new SignatureValidationContext(validationCertPool);
		
		final XmlDiagnosticData diagnosticData = prepareDiagnosticDataBuilder(validationContext).build();

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
	 * Creates a DiagnosticData to pass to the validation process
	 * 
	 * @param validationContext {@link ValidationContext}
	 * @return {@link DiagnosticData}
	 */
	protected DiagnosticDataBuilder prepareDiagnosticDataBuilder(final ValidationContext validationContext) {
		List<AdvancedSignature> allSignatures = getAllSignatures();
		List<TimestampToken> externalTimestamps = getExternalTimestamps();
		
		prepareCertificateVerifier(allSignatures, externalTimestamps);
		prepareSignatureValidationContext(validationContext, allSignatures);
		prepareTimestampValidationContext(validationContext, externalTimestamps);
		
		validateContext(validationContext);

		return new DiagnosticDataBuilder().document(document).foundSignatures(allSignatures)
				.usedTimestamps(validationContext.getProcessedTimestamps())
				.usedCertificates(validationContext.getProcessedCertificates())
				.usedRevocations(validationContext.getProcessedRevocations())
				.signatureScope(getSignatureScope(allSignatures, externalTimestamps))
				.setDefaultDigestAlgorithm(certificateVerifier.getDefaultDigestAlgorithm())
				.includeRawCertificateTokens(certificateVerifier.isIncludeCertificateTokenValues())
				.includeRawRevocationData(certificateVerifier.isIncludeCertificateRevocationValues())
				.includeRawTimestampTokens(certificateVerifier.isIncludeTimestampTokenValues())
				.certificateSourceTypes(validationContext.getCertificateSourceTypes())
				.trustedCertificateSources(certificateVerifier.getTrustedCertSources())
				.validationDate(getValidationTime());
	}

	/**
	 * This method returns the list of all signatures including the
	 * counter-signatures.
	 *
	 * @return {@code List} of {@code AdvancedSignature} to validate
	 */
	protected List<AdvancedSignature> getAllSignatures() {
		// not implemented by default
		// requires an implementation of {@code SignatureValidator}
		return Collections.emptyList();
	}
	
	protected List<TimestampToken> getExternalTimestamps() {
		// not implemented by default
		// requires an implementation of {@code SignatureValidator}
		return Collections.emptyList();
	}
//
//	/**
//	 * Returns a map between {@code TimestampToken}s to be validated and their {@code SignatureScope}s
//	 * 
//	 * @return a map between {@link TimestampToken}s and {@link SignatureScope}s
//	 */
//	protected Map<TimestampToken, List<SignatureScope>> getTimestamps() {
//		// not implemented by default
//		// requires an implementation of {@code TimestampValidator}
//		return Collections.emptyMap();
//	}
	
	protected void prepareCertificateVerifier(final Collection<AdvancedSignature> allSignatureList, final Collection<TimestampToken> externalTimestamps) {
		populateSignatureCrlSource(allSignatureList, externalTimestamps);
		populateSignatureOcspSource(allSignatureList, externalTimestamps);
	}
	
	/**
	 * Prepares the {@code validationContext} for signature validation process and returns a list of signatures to validate
	 * 
	 * @param validationContext {@link ValidationContext}
	 * @param allSignatures a list of all {@link AdvancedSignature}s to be validated
	 */
	protected void prepareSignatureValidationContext(final ValidationContext validationContext, 
			final List<AdvancedSignature> allSignatures) {
		// not implemented by default
		// see {@code SignedDocumentValidator}
	}
	
	/**
	 * Prepares the {@code validationContext} for a timestamp validation process
	 * 
	 * @param validationContext
	 *                          {@link ValidationContext}
	 * @param timestamps
	 *                          a list of timestamps
	 */
	protected void prepareTimestampValidationContext(final ValidationContext validationContext, List<TimestampToken> timestamps) {
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

	/**
	 * For all signatures to be validated this method merges the CRL sources.
	 *
	 * @param allSignatureList
	 *                           {@code Collection} of {@code AdvancedSignature}s to
	 *                           validate including the countersignatures
	 * @param externalTimestamps
	 *                           {@code Collection} of {@code TimestampToken}s to
	 *                           validate
	 */
	private void populateSignatureCrlSource(final Collection<AdvancedSignature> allSignatureList, final Collection<TimestampToken> externalTimestamps) {
		ListCRLSource allCrlSource = new ListCRLSource();
		if (Utils.isCollectionNotEmpty(allSignatureList)) {
			for (final AdvancedSignature signature : allSignatureList) {
				allCrlSource.addAll(signature.getCRLSource());
				allCrlSource.addAll(signature.getTimestampSource().getCRLSources());
			}
		}
		if (Utils.isCollectionNotEmpty(externalTimestamps)) {
			for (final TimestampToken timestampToken : externalTimestamps) {
				allCrlSource.addAll(timestampToken.getCRLSource());
			}
		}
		certificateVerifier.setSignatureCRLSource(allCrlSource);
	}

	/**
	 * For all signatures to be validated this method merges the OCSP sources.
	 *
	 * @param allSignatureList
	 *                           {@code Collection} of {@code AdvancedSignature}s to
	 *                           validate including the countersignatures
	 * @param externalTimestamps
	 *                           {@code Collection} of {@code TimestampToken}s to
	 *                           validate
	 * @return {@code ListOCSPSource}
	 */
	private void populateSignatureOcspSource(final Collection<AdvancedSignature> allSignatureList, final Collection<TimestampToken> externalTimestamps) {
		ListOCSPSource allOcspSource = new ListOCSPSource();
		if (Utils.isCollectionNotEmpty(allSignatureList)) {
			for (final AdvancedSignature signature : allSignatureList) {
				allOcspSource.addAll(signature.getOCSPSource());
				allOcspSource.addAll(signature.getTimestampSource().getOCSPSources());
			}
		}
		if (Utils.isCollectionNotEmpty(externalTimestamps)) {
			for (final TimestampToken timestampToken : externalTimestamps) {
				allOcspSource.addAll(timestampToken.getOCSPSource());
			}
		}
		certificateVerifier.setSignatureOCSPSource(allOcspSource);
	}
	
	/**
	 * Build a list of {@code SignatureScope} to add to Diagnostic Data
	 * 
	 * @param signatures
	 *                   a list of {@link AdvancedSignature}s (in case if present)
	 * @param timestamps
	 *                   a list of {@link TimestampToken}s
	 * @return a list of {@link SignatureScope}s
	 */
	protected List<SignatureScope> getSignatureScope(List<AdvancedSignature> signatures, List<TimestampToken> timestamps) {
		List<SignatureScope> signatureScopes = new ArrayList<SignatureScope>();
		if (Utils.isCollectionNotEmpty(signatures)) {
			for (AdvancedSignature signature : signatures) {
				signatureScopes.addAll(signature.getSignatureScopes());
			}
		}

		if (Utils.isCollectionNotEmpty(timestamps)) {
			for (TimestampToken timestampToken : timestamps) {
				List<TimestampedReference> timestampedReferences = timestampToken.getTimestampedReferences();
				// TODO
			}
		}

		return signatureScopes;
	}

	/**
	 * Executes the validation regarding to the given {@code validationPolicy}
	 * 
	 * @param diagnosticData {@link DiagnosticData} contained a data to be validated
	 * @param validationPolicy {@link ValidationPolicy}
	 * @return validation {@link Reports}
	 */
	protected final Reports processValidationPolicy(XmlDiagnosticData diagnosticData, ValidationPolicy validationPolicy) {
		final DocumentProcessExecutor executor = provideProcessExecutorInstance();
		executor.setValidationPolicy(validationPolicy);
		executor.setValidationLevel(validationLevel);
		executor.setDiagnosticData(diagnosticData);
		executor.setEnableEtsiValidationReport(enableEtsiValidationReport);
		executor.setCurrentTime(getValidationTime());
		return executor.execute();
	}

}
