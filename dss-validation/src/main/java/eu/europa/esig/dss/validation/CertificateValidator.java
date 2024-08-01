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

import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.TokenExtractionStrategy;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.identifier.OriginalIdentifierProvider;
import eu.europa.esig.dss.model.identifier.TokenIdentifierProvider;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.policy.ValidationPolicy;
import eu.europa.esig.dss.policy.ValidationPolicyFacade;
import eu.europa.esig.dss.spi.exception.IllegalInputException;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.spi.validation.CertificateVerifierBuilder;
import eu.europa.esig.dss.spi.validation.SignatureValidationContext;
import eu.europa.esig.dss.spi.validation.ValidationContext;
import eu.europa.esig.dss.spi.validation.executor.ValidationContextExecutor;
import eu.europa.esig.dss.validation.executor.ProcessExecutorProvider;
import eu.europa.esig.dss.validation.executor.certificate.CertificateProcessExecutor;
import eu.europa.esig.dss.validation.executor.certificate.DefaultCertificateProcessExecutor;
import eu.europa.esig.dss.spi.validation.executor.DefaultValidationContextExecutor;
import eu.europa.esig.dss.validation.reports.CertificateReports;
import eu.europa.esig.dss.validation.reports.diagnostic.CertificateDiagnosticDataBuilder;
import eu.europa.esig.dss.validation.reports.diagnostic.DiagnosticDataBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.InputStream;
import java.util.Date;
import java.util.Locale;
import java.util.Objects;

/**
 * Validates a CertificateToken
 */
public class CertificateValidator implements ProcessExecutorProvider<CertificateProcessExecutor> {

	private static final Logger LOG = LoggerFactory.getLogger(CertificateValidator.class);

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
		ValidationPolicy defaultPolicy;
		try {
			defaultPolicy = ValidationPolicyFacade.newFacade().getCertificateValidationPolicy();
		} catch (Exception e) {
			throw new DSSException("Unable to load the default policy", e);
		}
		return validate(defaultPolicy);
	}

	/**
	 * This method validates a certificate with the given validation policy {@code InputStream}
	 *
	 * @param policyDataStream {@link InputStream} representing the XML Validation Policy file
	 * @return {@link CertificateReports}
	 */
	public CertificateReports validate(InputStream policyDataStream) {
		try {
			if (policyDataStream == null) {
				LOG.debug("No provided validation policy : use the default policy");
				return validate();

			} else {
				ValidationPolicy validationPolicy = ValidationPolicyFacade.newFacade().getValidationPolicy(policyDataStream);
				return validate(validationPolicy);
			}

		} catch (Exception e) {
			throw new IllegalInputException("Unable to load the policy", e);
		}
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
