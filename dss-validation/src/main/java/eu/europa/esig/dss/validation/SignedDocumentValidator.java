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
import eu.europa.esig.dss.enumerations.ValidationLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.ManifestFile;
import eu.europa.esig.dss.model.identifier.TokenIdentifierProvider;
import eu.europa.esig.dss.policy.EtsiValidationPolicy;
import eu.europa.esig.dss.policy.ValidationPolicy;
import eu.europa.esig.dss.policy.ValidationPolicyFacade;
import eu.europa.esig.dss.policy.jaxb.ConstraintsParameters;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.exception.IllegalInputException;
import eu.europa.esig.dss.spi.policy.SignaturePolicyProvider;
import eu.europa.esig.dss.spi.policy.SignaturePolicyValidatorLoader;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.spi.validation.ValidationContext;
import eu.europa.esig.dss.spi.validation.ValidationDataContainer;
import eu.europa.esig.dss.spi.validation.analyzer.DefaultDocumentAnalyzer;
import eu.europa.esig.dss.spi.validation.analyzer.DocumentAnalyzer;
import eu.europa.esig.dss.spi.validation.executor.ValidationContextExecutor;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.spi.x509.evidencerecord.EvidenceRecord;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.executor.DocumentProcessExecutor;
import eu.europa.esig.dss.validation.executor.signature.DefaultSignatureProcessExecutor;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.validation.reports.diagnostic.SignedDocumentDiagnosticDataBuilder;
import eu.europa.esig.dss.validation.reports.diagnostic.XmlDiagnosticDataFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.util.Collection;
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

	/**
	 * This class performs analysis of the document, tokens extraction as well as cryptographic validation
	 */
	protected final DocumentAnalyzer documentAnalyzer;

	/**
	 * This variable can hold a specific {@code DocumentProcessExecutor}
	 */
	protected DocumentProcessExecutor processExecutor = null;

	/**
	 * This variable set the default Digest Algorithm what will be used for calculation
	 * of digests for validation tokens and signed data
	 * Default: SHA256
	 */
	private DigestAlgorithm defaultDigestAlgorithm = DigestAlgorithm.SHA256;

	/**
	 * The used token extraction strategy to define tokens representation in DiagnosticData
	 */
	private TokenExtractionStrategy tokenExtractionStrategy = TokenExtractionStrategy.NONE;

	/**
	 * This variable allows to include the semantics for Indication / SubIndication
	 */
	private boolean includeSemantics = false;

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
	 * The constructor with a null {@code signatureScopeFinder}
	 *
	 * @param documentAnalyzer {@link eu.europa.esig.dss.spi.validation.analyzer.DocumentAnalyzer}
	 */
	protected SignedDocumentValidator(final DocumentAnalyzer documentAnalyzer) {
		Objects.requireNonNull(documentAnalyzer, "DocumentAnalyzer cannot be null!");
		this.documentAnalyzer = documentAnalyzer;
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
		throw new UnsupportedOperationException("Document format not recognized/handled");
	}

	/**
	 * Checks if the document is supported by the current validator
	 *
	 * @param dssDocument {@link DSSDocument} to check
	 * @return TRUE if the document is supported, FALSE otherwise
	 */
	public boolean isSupported(DSSDocument dssDocument) {
		return documentAnalyzer.isSupported(dssDocument);
	}

	/**
	 * Returns the current instance of {@code DocumentAnalyzer}
	 *
	 * @return {@link eu.europa.esig.dss.spi.validation.analyzer.DocumentAnalyzer}
	 */
	public eu.europa.esig.dss.spi.validation.analyzer.DocumentAnalyzer getDocumentAnalyzer() {
		return documentAnalyzer;
	}

	@Override
	public void setSigningCertificateSource(CertificateSource signingCertificateSource) {
		documentAnalyzer.setSigningCertificateSource(signingCertificateSource);
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
		documentAnalyzer.setCertificateVerifier(certificateVerifier);
	}

	@Override
	public void setValidationContextExecutor(ValidationContextExecutor validationContextExecutor) {
		documentAnalyzer.setValidationContextExecutor(validationContextExecutor);
	}

	@Override
	public void setTokenIdentifierProvider(TokenIdentifierProvider tokenIdentifierProvider) {
		documentAnalyzer.setTokenIdentifierProvider(tokenIdentifierProvider);
	}

	@Override
	public void setDetachedContents(final List<DSSDocument> detachedContents) {
		documentAnalyzer.setDetachedContents(detachedContents);
	}

	@Override
	public void setDetachedEvidenceRecordDocuments(final List<DSSDocument> detachedEvidenceRecordDocuments) {
		documentAnalyzer.setDetachedEvidenceRecordDocuments(detachedEvidenceRecordDocuments);
	}

	@Override
	public void setContainerContents(List<DSSDocument> containerContents) {
		documentAnalyzer.setContainerContents(containerContents);
	}
	
	@Override
	public void setManifestFile(ManifestFile manifestFile) {
		documentAnalyzer.setManifestFile(manifestFile);
	}

	/**
	 * Allows to define a custom validation time
	 * 
	 * @param validationTime {@link Date}
	 */
	@Override
	public void setValidationTime(Date validationTime) {
		documentAnalyzer.setValidationTime(validationTime);
	}

	@Override
	public void setSignaturePolicyProvider(SignaturePolicyProvider signaturePolicyProvider) {
		documentAnalyzer.setSignaturePolicyProvider(signaturePolicyProvider);
	}

	@Override
	public void setDefaultDigestAlgorithm(DigestAlgorithm digestAlgorithm) {
		Objects.requireNonNull(digestAlgorithm, "Default DigestAlgorithm cannot be nulL!");
		this.defaultDigestAlgorithm = digestAlgorithm;
	}

	@Override
	public void setTokenExtractionStrategy(TokenExtractionStrategy tokenExtractionStrategy) {
		Objects.requireNonNull(tokenExtractionStrategy);
		this.tokenExtractionStrategy = tokenExtractionStrategy;
	}

	@Override
	public void setIncludeSemantics(boolean include) {
		this.includeSemantics = include;
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
	 * Sets Locale for report messages generation
	 *
	 * @param locale {@link Locale}
	 */
	public void setLocale(Locale locale) {
		this.locale = locale;
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
		try (InputStream is = validationPolicyURL.openStream()) {
			return validateDocument(is);
		} catch (IOException e) {
			throw new IllegalInputException(String.format("Unable to load policy with URL '%s'. Reason : %s",
					validationPolicyURL, e.getMessage()), e);
		}
	}

	@Override
	public Reports validateDocument(final String policyResourcePath) {
		if (policyResourcePath == null) {
			return validateDocument((InputStream) null);
		}
		try (InputStream is = getClass().getResourceAsStream(policyResourcePath)) {
			return validateDocument(is);
		} catch (IOException e) {
			throw new IllegalInputException(String.format("Unable to load policy from path '%s'. Reason : %s",
					policyResourcePath, e.getMessage()), e);
		}
	}

	@Override
	public Reports validateDocument(final File policyFile) {
		if ((policyFile == null) || !policyFile.exists()) {
			return validateDocument((InputStream) null);
		}
		try (InputStream is = DSSUtils.toByteArrayInputStream(policyFile)) {
			return validateDocument(is);
		} catch (IOException e) {
			throw new IllegalInputException(String.format("Unable to load policy from file '%s'. Reason : %s",
					policyFile, e.getMessage()), e);
		}
	}

	@Override
	public Reports validateDocument(DSSDocument policyDocument) {
		try (InputStream is = policyDocument.openStream()) {
			return validateDocument(is);
		} catch (IOException e) {
			throw new DSSException(String.format("Unable to read policy file: %s", e.getMessage()), e);
		}
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
		ValidationPolicy validationPolicy;
		try {
			if (policyDataStream == null) {
				LOG.debug("No provided validation policy : use the default policy");
				validationPolicy = ValidationPolicyFacade.newFacade().getDefaultValidationPolicy();
			} else {
				validationPolicy = ValidationPolicyFacade.newFacade().getValidationPolicy(policyDataStream);
			}
		} catch (Exception e) {
			throw new IllegalInputException("Unable to load the policy", e);
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

		final XmlDiagnosticData diagnosticData = getDiagnosticData();

		return processValidationPolicy(diagnosticData, validationPolicy);
	}

	/**
	 * This method verifies whether the configuration of the current instance of a document validator is valid
	 */
	protected void assertConfigurationValid() {
		if (ValidationLevel.BASIC_SIGNATURES == validationLevel
				&& (Utils.isCollectionNotEmpty(documentAnalyzer.getDetachedTimestamps()) || Utils.isCollectionNotEmpty(documentAnalyzer.getDetachedEvidenceRecords()))
				&& Utils.isCollectionEmpty(documentAnalyzer.getSignatures())) {
			throw new IllegalArgumentException("Basic Signatures validation cannot be used for timestamp or evidence record documents!");
		}
	}

	/**
	 * This method retrieves {@code XmlDiagnosticData} containing all information relevant
	 * for the validation process, including the certificate and revocation tokens obtained
	 * from online resources, e.g. AIA, CRL, OCSP (when applicable).
	 *
	 * @return {@link XmlDiagnosticData}
	 */
	public final XmlDiagnosticData getDiagnosticData() {
		ValidationContext validationContext = documentAnalyzer.validate();
		SignedDocumentDiagnosticDataBuilder diagnosticDataBuilder = initializeDiagnosticDataBuilder();
		return new XmlDiagnosticDataFactory(diagnosticDataBuilder)
				.setDocument(documentAnalyzer.getDocument())
				.setValidationTime(documentAnalyzer.getValidationTime())
				.setTokenIdentifierProvider(documentAnalyzer.getTokenIdentifierProvider())
				.setValidationContext(validationContext)
				.setDefaultDigestAlgorithm(defaultDigestAlgorithm)
				.setTokenExtractionStrategy(tokenExtractionStrategy)
				.create();
	}

	/**
	 * This method creates a format-specific implementation of the {@code SignedDocumentDiagnosticDataBuilder}
	 *
	 * @return {@link SignedDocumentDiagnosticDataBuilder}
	 */
	protected SignedDocumentDiagnosticDataBuilder initializeDiagnosticDataBuilder() {
		// default implementation
		return new SignedDocumentDiagnosticDataBuilder();
	}

	/**
	 * Executes the validation regarding the given {@code validationPolicy}
	 * 
	 * @param diagnosticData   {@link DiagnosticData} contained a data to be
	 *                         validated
	 * @param validationPolicy {@link ValidationPolicy}
	 * @return validation {@link Reports}
	 */
	protected final Reports processValidationPolicy(XmlDiagnosticData diagnosticData, ValidationPolicy validationPolicy) {
		final DocumentProcessExecutor executor = provideProcessExecutorInstance();
		executor.setCurrentTime(documentAnalyzer.getValidationTime());
		executor.setValidationPolicy(validationPolicy);
		executor.setValidationLevel(validationLevel);
		executor.setDiagnosticData(diagnosticData);
		executor.setIncludeSemantics(includeSemantics);
		executor.setEnableEtsiValidationReport(enableEtsiValidationReport);
		executor.setLocale(locale);
		return executor.execute();
	}

	@Override
	public List<AdvancedSignature> getSignatures() {
		return documentAnalyzer.getSignatures();
	}

	/**
	 * Returns the signature with the given id. Processes custom {@code TokenIdentifierProvider} and counter signatures
	 *
	 * @param signatureId {@link String} id of a signature to be extracted
	 * @return {@link AdvancedSignature} with the given id if found, NULL otherwise
	 */
	public AdvancedSignature getSignatureById(String signatureId) {
		if (documentAnalyzer instanceof DefaultDocumentAnalyzer) {
			return ((DefaultDocumentAnalyzer) documentAnalyzer).getSignatureById(signatureId);
		}
		throw new IllegalStateException("The documentAnalyzer shall be an instance of DefaultDocumentAnalyzer to execute the method!");
	}

	@Override
	public List<TimestampToken> getDetachedTimestamps() {
		return documentAnalyzer.getDetachedTimestamps();
	}

	@Override
	public List<EvidenceRecord> getDetachedEvidenceRecords() {
		return documentAnalyzer.getDetachedEvidenceRecords();
	}

	@Override
	public List<DSSDocument> getOriginalDocuments(String signatureId) {
		return documentAnalyzer.getOriginalDocuments(signatureId);
	}

	@Override
	public List<DSSDocument> getOriginalDocuments(AdvancedSignature advancedSignature) {
		return documentAnalyzer.getOriginalDocuments(advancedSignature);
	}

	@Override
	public <T extends AdvancedSignature> ValidationDataContainer getValidationData(Collection<T> signatures) {
		return documentAnalyzer.getValidationData(signatures);
	}

	@Override
	public <T extends AdvancedSignature> ValidationDataContainer getValidationData(Collection<T> signatures, Collection<TimestampToken> detachedTimestamps) {
		return documentAnalyzer.getValidationData(signatures, detachedTimestamps);
	}

	/**
	 * Returns an instance of a corresponding to the format {@code SignaturePolicyValidatorLoader}
	 *
	 * @return {@link SignaturePolicyValidatorLoader}
	 */
	public SignaturePolicyValidatorLoader getSignaturePolicyValidatorLoader() {
		if (documentAnalyzer instanceof DefaultDocumentAnalyzer) {
			return ((DefaultDocumentAnalyzer) documentAnalyzer).getSignaturePolicyValidatorLoader();
		}
		throw new IllegalStateException("The documentAnalyzer shall be an instance of DefaultDocumentAnalyzer to execute the method!");
	}

}
