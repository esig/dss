/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.validation;

import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.TokenExtractionStrategy;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.identifier.OriginalIdentifierProvider;
import eu.europa.esig.dss.model.identifier.TokenIdentifierProvider;
import eu.europa.esig.dss.model.policy.ValidationPolicy;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.exception.IllegalInputException;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.spi.validation.CertificateVerifierBuilder;
import eu.europa.esig.dss.spi.validation.SignatureValidationContext;
import eu.europa.esig.dss.spi.validation.ValidationContext;
import eu.europa.esig.dss.spi.validation.executor.DefaultValidationContextExecutor;
import eu.europa.esig.dss.spi.validation.executor.ValidationContextExecutor;
import eu.europa.esig.dss.validation.executor.ProcessExecutorProvider;
import eu.europa.esig.dss.validation.executor.certificate.CertificateProcessExecutor;
import eu.europa.esig.dss.validation.executor.certificate.DefaultCertificateProcessExecutor;
import eu.europa.esig.dss.validation.policy.ValidationPolicyLoader;
import eu.europa.esig.dss.validation.reports.CertificateReports;
import eu.europa.esig.dss.validation.reports.diagnostic.CertificateDiagnosticDataBuilder;
import eu.europa.esig.dss.validation.reports.diagnostic.DiagnosticDataBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.util.Date;
import java.util.Locale;
import java.util.Objects;

/**
 * Validates a CertificateToken
 */
public class CertificateValidator implements ProcessExecutorProvider<CertificateProcessExecutor> {

	private static final Logger LOG = LoggerFactory.getLogger(CertificateValidator.class);

	/** The path for default certificate validation policy */
	private static final String CERTIFICATE_VALIDATION_POLICY_LOCATION = "/policy/certificate-constraint.xml";

	/** The certificateToken to be validated */
	private final CertificateToken token;

	/** The validation time */
	private Date validationTime;

	/** The CertificateVerifier to use */
	private CertificateVerifier certificateVerifier;

	/** The TokenExtractionStrategy */
	private TokenExtractionStrategy tokenExtractionStrategy = TokenExtractionStrategy.NONE;

	/** The token identifier provider to use */
	private TokenIdentifierProvider identifierProvider = new OriginalIdentifierProvider();

	/**
	 * Performs validation of {@code ValidationContext}
	 * Default : {@code DefaultValidationContextExecutor}
	 */
	private ValidationContextExecutor validationContextExecutor = DefaultValidationContextExecutor.INSTANCE;
	
	/**
	 * Locale to use for reports generation
	 * By default a Locale from OS is used
	 */
	private Locale locale = Locale.getDefault();

	/** The CertificateProcessExecutor */
	private CertificateProcessExecutor processExecutor;

	/**
	 * This variable set the default Digest Algorithm what will be used for calculation
	 * of digests for validation tokens and signed data
	 * Default: SHA256
	 */
	private DigestAlgorithm defaultDigestAlgorithm = DigestAlgorithm.SHA256;

	/**
	 * The default constructor
	 *
	 * @param token {@link CertificateToken}
	 */
	private CertificateValidator(CertificateToken token) {
		Objects.requireNonNull(token, "The certificate is missing");
		this.token = token;
	}

	/**
	 * Creates a CertificateValidator from a certificateToken
	 *
	 * @param token {@link CertificateToken}
	 * @return {@link CertificateValidator}
	 */
	public static CertificateValidator fromCertificate(final CertificateToken token) {
		return new CertificateValidator(token);
	}

	/**
	 * Sets the CertificateVerifier
	 *
	 * @param certificateVerifier {@link CertificateVerifier}
	 */
	public void setCertificateVerifier(CertificateVerifier certificateVerifier) {
		this.certificateVerifier = certificateVerifier;
	}

	/**
	 * Sets the TokenExtractionStrategy
	 *
	 * @param tokenExtractionStrategy {@link TokenExtractionStrategy}
	 */
	public void setTokenExtractionStrategy(TokenExtractionStrategy tokenExtractionStrategy) {
		Objects.requireNonNull(tokenExtractionStrategy);
		this.tokenExtractionStrategy = tokenExtractionStrategy;
	}

	/**
	 * Sets the TokenIdentifierProvider
	 *
	 * @param identifierProvider {@link TokenIdentifierProvider}
	 */
	public void setTokenIdentifierProvider(TokenIdentifierProvider identifierProvider) {
		Objects.requireNonNull(identifierProvider);
		this.identifierProvider = identifierProvider;
	}

	/**
	 * Sets the validationTime
	 *
	 * @param validationTime {@link Date}
	 */
	public void setValidationTime(Date validationTime) {
		this.validationTime = validationTime;
	}

	/**
	 * Sets the Locale to use for messages in reports
	 *
	 * @param locale {@link Locale}
	 */
	public void setLocale(Locale locale) {
		this.locale = locale;
	}
	
	private Date getValidationTime() {
		if (validationTime == null) {
			validationTime = new Date();
		}
		return validationTime;
	}

	/**
	 * This method sets {@code ValidationContextExecutor} for validation of the prepared {@code ValidationContext}
	 * Default: {@code eu.europa.esig.dss.validation.executor.context.DefaultValidationContextExecutor}
	 *          (performs basic validation of tokens, including certificate chain building and
	 *          revocation data extraction, without processing of validity checks)
	 *
	 * @param validationContextExecutor {@link ValidationContextExecutor}
	 */
	public void setValidationContextExecutor(ValidationContextExecutor validationContextExecutor) {
		Objects.requireNonNull(validationContextExecutor);
		this.validationContextExecutor = validationContextExecutor;
	}

	/**
	 * This method allows to change the Digest Algorithm that will be used for tokens' digest calculation
	 * Default : {@code DigestAlgorithm.SHA256}
	 *
	 * @param digestAlgorithm {@link DigestAlgorithm} to use
	 */
	public void setDefaultDigestAlgorithm(DigestAlgorithm digestAlgorithm) {
		Objects.requireNonNull(digestAlgorithm, "Default DigestAlgorithm cannot be nulL!");
		this.defaultDigestAlgorithm = digestAlgorithm;
	}

	/**
	 * Validates the certificate with a default validation policy
	 *
	 * @return {@link CertificateReports}
	 */
	public CertificateReports validate() {
		return validate((DSSDocument) null);
	}

	/**
	 * Validates the certificate with the validation policy obtained from {@code validationPolicyURL}.
	 * If null the default file is used.
	 *
	 * @param validationPolicyURL {@link URL}
	 * @return {@link CertificateReports}
	 */
	public CertificateReports validate(final URL validationPolicyURL) {
		return validate(validationPolicyURL, null);
	}

	/**
	 * Validates the certificate with the validation policy obtained from {@code policyResourcePath}.
	 * If null or empty the default file is used.
	 *
	 * @param policyResourcePath
	 *            is located against the classpath (getClass().getResourceAsStream), and NOT the filesystem
	 * @return {@link CertificateReports}
	 */
	public CertificateReports validate(final String policyResourcePath) {
		return validate(policyResourcePath, null);
	}

	/**
	 * Validates the certificate with the validation policy obtained from {@code policyFile}.
	 * If null or file does not exist the default file is used.
	 *
	 * @param policyFile
	 *            contains the validation policy (xml) as {@code File}
	 * @return {@link CertificateReports}
	 */
	public CertificateReports validate(final File policyFile) {
		return validate(policyFile, null);
	}

	/**
	 * Validates the certificate with the validation policy obtained from {@code policyDocument}.
	 * If null the default file is used.
	 *
	 * @param policyDocument
	 *            contains the validation policy (xml) as {@code DSSDocument}
	 * @return {@link CertificateReports}
	 */
	public CertificateReports validate(DSSDocument policyDocument) {
		return validate(policyDocument, null);
	}

	/**
	 * Validates the document and all its signatures. The policyDataStream contains
	 * the constraint file. If null the default file is used.
	 *
	 * @param policyDataStream the {@code InputStream} with the validation policy
	 * @return {@link CertificateReports}
	 */
	public CertificateReports validate(final InputStream policyDataStream) {
		return validate(policyDataStream, null);
	}

	/**
	 * Validates the certificate using the provided validation policy and a cryptographic suite.
	 * If cryptographic suite is set, the constraints from validation policy will be overwritten
	 * by the constraints retrieved from the cryptographic suite.
	 * When set, the cryptographic suite constraints are applied with the default behavior, using FAIL level.
	 * For a customizable cryptographic suite and its applicability context,
	 * please use {@code eu.europa.esig.dss.validation.policy.ValidationPolicyLoader}.
	 * <p>
	 * The format of validation policy should correspond to the DSS XML Validation policy
	 * (please include 'dss-policy-jaxb' module in your classpath), unless a custom validation policy has been implemented.
	 * The format of cryptographic suite should correspond to XML or JSON schema as defined in ETSI TS 119 322
	 * (please include 'dss-policy-crypto-xml' or 'dss-policy-crypto-json' to the classpath), unless a custom
	 * cryptographic suite has been implemented.
	 * <p>
	 * If the validation policy URL is set then the policy constraints
	 * are retrieved from this location. If null or empty the default file is used.
	 *
	 * @param validationPolicyURL {@link URL} to the used validation policy file
	 * @param cryptographicSuiteURL {@link URL} to the used cryptographic suite file
	 * @return {@link CertificateReports}
	 */
	public CertificateReports validate(URL validationPolicyURL, URL cryptographicSuiteURL) {
		try (InputStream validationPolicyIS = validationPolicyURL != null ? validationPolicyURL.openStream() : null ;
			 InputStream cryptographicSuiteIS = cryptographicSuiteURL != null ? cryptographicSuiteURL.openStream() : null) {
			return validate(validationPolicyIS, cryptographicSuiteIS);
		} catch (IOException e) {
			throw new IllegalInputException(String.format(
					"Unable to load policy with URL '%s' and cryptographic suite '%s'. Reason : %s",
					validationPolicyURL, cryptographicSuiteURL, e.getMessage()), e);
		}
	}

	/**
	 * Validates the certificate using the provided validation policy and a cryptographic suite.
	 * If cryptographic suite is set, the constraints from validation policy will be overwritten
	 * by the constraints retrieved from the cryptographic suite.
	 * When set, the cryptographic suite constraints are applied with the default behavior, using FAIL level.
	 * For a customizable cryptographic suite and its applicability context,
	 * please use {@code eu.europa.esig.dss.validation.policy.ValidationPolicyLoader}.
	 * <p>
	 * The format of validation policy should correspond to the DSS XML Validation policy
	 * (please include 'dss-policy-jaxb' module in your classpath), unless a custom validation policy has been implemented.
	 * The format of cryptographic suite should correspond to XML or JSON schema as defined in ETSI TS 119 322
	 * (please include 'dss-policy-crypto-xml' or 'dss-policy-crypto-json' to the classpath), unless a custom
	 * cryptographic suite has been implemented.
	 * <p>
	 * The {@code policyResourcePath} and {@code cryptographicSuitePath} specify the constraint file.
	 * If null or empty the default file is used.
	 *
	 * @param policyResourcePath
	 *            {@link String} path to the validation policy file, located against
	 *            the classpath (getClass().getResourceAsStream), and NOT the filesystem
	 * @param cryptographicSuitePath
	 *            {@link String} path to the cryptographic suite file, located against
	 *            the classpath (getClass().getResourceAsStream), and NOT the filesystem
	 * @return {@link CertificateReports}
	 */
	public CertificateReports validate(String policyResourcePath, String cryptographicSuitePath) {
		try (InputStream validationPolicyIS = policyResourcePath != null ? getClass().getResourceAsStream(policyResourcePath) : null ;
			 InputStream cryptographicSuiteIS = cryptographicSuitePath != null ? getClass().getResourceAsStream(cryptographicSuitePath) : null) {
			return validate(validationPolicyIS, cryptographicSuiteIS);
		} catch (IOException e) {
			throw new IllegalInputException(String.format(
					"Unable to load policy with URL '%s' and cryptographic suite '%s'. Reason : %s",
					policyResourcePath, cryptographicSuitePath, e.getMessage()), e);
		}
	}

	/**
	 * Validates the certificate using the provided validation policy and a cryptographic suite.
	 * If cryptographic suite is set, the constraints from validation policy will be overwritten
	 * by the constraints retrieved from the cryptographic suite.
	 * When set, the cryptographic suite constraints are applied with the default behavior, using FAIL level.
	 * For a customizable cryptographic suite and its applicability context,
	 * please use {@code eu.europa.esig.dss.validation.policy.ValidationPolicyLoader}.
	 * <p>
	 * The format of validation policy should correspond to the DSS XML Validation policy
	 * (please include 'dss-policy-jaxb' module in your classpath), unless a custom validation policy has been implemented.
	 * The format of cryptographic suite should correspond to XML or JSON schema as defined in ETSI TS 119 322
	 * (please include 'dss-policy-crypto-xml' or 'dss-policy-crypto-json' to the classpath), unless a custom
	 * cryptographic suite has been implemented.
	 * <p>
	 * The {@code File} parameters specify the constraint file. If null the default file is used.
	 *
	 * @param policyFile
	 *            {@link File} containing the validation policy
	 * @param cryptographicSuiteFile
	 *            {@link File} containing the cryptographic suite
	 * @return {@link CertificateReports}
	 */
	public CertificateReports validate(File policyFile, File cryptographicSuiteFile) {
		DSSDocument policyDocument = policyFile != null ? new FileDocument(policyFile) : null;
		DSSDocument cryptographicSuiteDocument = cryptographicSuiteFile != null ? new FileDocument(cryptographicSuiteFile) : null;
		return validate(policyDocument, cryptographicSuiteDocument);
	}

	/**
	 * Validates the certificate using the provided validation policy and a cryptographic suite.
	 * If cryptographic suite is set, the constraints from validation policy will be overwritten
	 * by the constraints retrieved from the cryptographic suite.
	 * When set, the cryptographic suite constraints are applied with the default behavior, using FAIL level.
	 * For a customizable cryptographic suite and its applicability context,
	 * please use {@code eu.europa.esig.dss.validation.policy.ValidationPolicyLoader}.
	 * <p>
	 * The format of validation policy should correspond to the DSS XML Validation policy
	 * (please include 'dss-policy-jaxb' module in your classpath), unless a custom validation policy has been implemented.
	 * The format of cryptographic suite should correspond to XML or JSON schema as defined in ETSI TS 119 322
	 * (please include 'dss-policy-crypto-xml' or 'dss-policy-crypto-json' to the classpath), unless a custom
	 * cryptographic suite has been implemented.
	 * <p>
	 * The {@code DSSDocument} parameters contains the constraint files. If null the default file is used.
	 *
	 * @param policyDocument
	 *            {@link DSSDocument} containing the validation policy
	 * @param cryptographicSuiteDocument
	 *            {@link DSSDocument} containing the cryptographic suite
	 * @return {@link CertificateReports}
	 */
	public CertificateReports validate(DSSDocument policyDocument, DSSDocument cryptographicSuiteDocument) {
		ValidationPolicy validationPolicy = loadValidationPolicy(policyDocument, cryptographicSuiteDocument);
		return validate(validationPolicy);
	}

	/**
	 * This method loads a validation policy from the {@code policyDocument} and a {@code cryptographicSuiteDocument}.
	 * When a document is not provided, a default policy or cryptographic suite is used, respectively.
	 *
	 * @param policyDocument {@link DSSDocument} containing the validation policy document
	 * @param cryptographicSuiteDocument {@link DSSDocument} containing the cryptographic suite document
	 * @return {@link ValidationPolicy}
	 */
	protected ValidationPolicy loadValidationPolicy(DSSDocument policyDocument, DSSDocument cryptographicSuiteDocument) {
		try {
			ValidationPolicyLoader validationPolicyLoader;
			if (policyDocument == null) {
				LOG.debug("No provided validation policy : use the default policy");
				validationPolicyLoader = fromDefaultCertificateValidationPolicyLoader();
			} else {
				validationPolicyLoader = ValidationPolicyLoader.fromValidationPolicy(policyDocument);
			}
			if (cryptographicSuiteDocument != null) {
				validationPolicyLoader = validationPolicyLoader.withCryptographicSuite(cryptographicSuiteDocument);
			}

			return validationPolicyLoader.create();

		} catch (Exception e) {
			throw new IllegalInputException("Unable to load the policy", e);
		}
	}

	/**
	 * Gets a default validation policy loader for a certificate validation
	 *
	 * @return {@link ValidationPolicyLoader}
	 */
	protected ValidationPolicyLoader fromDefaultCertificateValidationPolicyLoader() {
		return ValidationPolicyLoader.fromValidationPolicy(
				CertificateValidator.class.getResourceAsStream(CERTIFICATE_VALIDATION_POLICY_LOCATION));
	}

	/**
	 * Validates the certificate using the provided validation policy and a cryptographic suite.
	 * If cryptographic suite is set, the constraints from validation policy will be overwritten
	 * by the constraints retrieved from the cryptographic suite.
	 * When set, the cryptographic suite constraints are applied with the default behavior, using FAIL level.
	 * For a customizable cryptographic suite and its applicability context,
	 * please use {@code eu.europa.esig.dss.validation.policy.ValidationPolicyLoader}.
	 * <p>
	 * The format of validation policy should correspond to the DSS XML Validation policy
	 * (please include 'dss-policy-jaxb' module in your classpath), unless a custom validation policy has been implemented.
	 * The format of cryptographic suite should correspond to XML or JSON schema as defined in ETSI TS 119 322
	 * (please include 'dss-policy-crypto-xml' or 'dss-policy-crypto-json' to the classpath), unless a custom
	 * cryptographic suite has been implemented.
	 * <p>
	 * The {@code InputStream} parameters contains the constraint files. If null the default file is used.
	 *
	 * @param policyDataStream
	 *            {@link InputStream} containing the validation policy
	 * @param cryptographicSuiteStream
	 *            {@link InputStream} containing the cryptographic suite
	 * @return {@link CertificateReports}
	 */
	public CertificateReports validate(InputStream policyDataStream, InputStream cryptographicSuiteStream) {
		DSSDocument policyDocument = policyDataStream != null ? new InMemoryDocument(policyDataStream) : null;
		DSSDocument cryptographicSuiteDocument = cryptographicSuiteStream != null ? new InMemoryDocument(cryptographicSuiteStream) : null;
		return validate(policyDocument, cryptographicSuiteDocument);
	}

	/**
	 * Validated the certificate with a custom validation policy
	 *
	 * @param validationPolicy {@link ValidationPolicy}
	 * @return {@link CertificateReports}
	 */
	public CertificateReports validate(ValidationPolicy validationPolicy) {
		assertConfigurationValid();

		final XmlDiagnosticData diagnosticData = getDiagnosticData();

		CertificateProcessExecutor executor = provideProcessExecutorInstance();
		executor.setValidationPolicy(validationPolicy);
		executor.setDiagnosticData(diagnosticData);
		executor.setCertificateId(identifierProvider.getIdAsString(token));
		executor.setLocale(locale);
		executor.setCurrentTime(getValidationTime());
		return executor.execute();
	}

	/**
	 * Checks if the Validator configuration is valid
	 */
	protected void assertConfigurationValid() {
		Objects.requireNonNull(certificateVerifier, "CertificateVerifier is not defined");
		Objects.requireNonNull(token, "Certificate token is not provided to the validator");
	}

	/**
	 * This method retrieves {@code XmlDiagnosticData} containing all information relevant
	 * for the validation process, including the certificate and revocation tokens obtained
	 * from online resources, e.g. AIA, CRL, OCSP (when applicable).
	 *
	 * @return {@link XmlDiagnosticData}
	 */
	public final XmlDiagnosticData getDiagnosticData() {
		return prepareDiagnosticDataBuilder().build();
	}

	/**
	 * Initializes and fills {@code ValidationContext} for a certificate token validation
	 *
	 * @param certificateVerifier {@link CertificateVerifier} to be used
	 * @return {@link ValidationContext}
	 */
	protected ValidationContext prepareValidationContext(CertificateVerifier certificateVerifier) {
		final ValidationContext svc = createValidationContext();
		svc.initialize(certificateVerifier);
		svc.addCertificateTokenForVerification(token);
		return svc;
	}

	/**
	 * This method creates a new instance of {@code ValidationContext} performing preparation of validation data,
	 * certificate chain building, revocation request, as well as custom validation checks execution.
	 *
	 * @return {@link ValidationContext}
	 */
	protected ValidationContext createValidationContext() {
		return new SignatureValidationContext(getValidationTime());
	}

	/**
	 * Creates a {@code DiagnosticDataBuilder}
	 *
	 * @return {@link DiagnosticDataBuilder}
	 */
	protected DiagnosticDataBuilder prepareDiagnosticDataBuilder() {
		final CertificateVerifier certificateVerifierForValidation =
				new CertificateVerifierBuilder(certificateVerifier).buildCompleteCopyForValidation();
		final ValidationContext validationContext = prepareValidationContext(certificateVerifierForValidation);
		validateContext(validationContext);
		return createDiagnosticDataBuilder(validationContext);
	}

	/**
	 * Process the validation
	 *
	 * @param validationContext {@link ValidationContext} to process
	 */
	protected void validateContext(final ValidationContext validationContext) {
		validationContextExecutor.validate(validationContext);
	}

	/**
	 * Creates and fills the {@code DiagnosticDataBuilder} with a relevant data
	 *
	 * @param validationContext {@link ValidationContext} used for the validation
	 * @return filled {@link DiagnosticDataBuilder}
	 */
	protected DiagnosticDataBuilder createDiagnosticDataBuilder(final ValidationContext validationContext) {
		return new CertificateDiagnosticDataBuilder()
				.usedCertificates(validationContext.getProcessedCertificates())
				.usedRevocations(validationContext.getProcessedRevocations())
				.allCertificateSources(validationContext.getAllCertificateSources())
				.defaultDigestAlgorithm(defaultDigestAlgorithm)
				.tokenExtractionStrategy(tokenExtractionStrategy)
				.tokenIdentifierProvider(identifierProvider)
				.validationDate(getValidationTime());
	}

	@Override
	public void setProcessExecutor(CertificateProcessExecutor processExecutor) {
		this.processExecutor = processExecutor;
	}

	/**
	 * Gets the {@link CertificateProcessExecutor}
	 *
	 * @return {@link CertificateProcessExecutor}
	 */
	public CertificateProcessExecutor provideProcessExecutorInstance() {
		if (processExecutor == null) {
			processExecutor = getDefaultProcessExecutor();
		}
		return processExecutor;
	}

	@Override
	public CertificateProcessExecutor getDefaultProcessExecutor() {
		return new DefaultCertificateProcessExecutor();
	}

}
