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
import eu.europa.esig.dss.enumerations.TokenExtractionStrategy;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.policy.ValidationPolicy;
import eu.europa.esig.dss.policy.ValidationPolicyFacade;
import eu.europa.esig.dss.validation.executor.certificate.CertificateProcessExecutor;
import eu.europa.esig.dss.validation.executor.certificate.DefaultCertificateProcessExecutor;
import eu.europa.esig.dss.validation.reports.CertificateReports;

import java.util.Date;
import java.util.Locale;
import java.util.Objects;

/**
 * Validates a CertificateToken
 */
public class CertificateValidator implements ProcessExecutorProvider<CertificateProcessExecutor> {

	/** The certificateToken to be validated */
	private final CertificateToken token;

	/** The validation time */
	private Date validationTime;

	/** The CertificateVerifier to use */
	private CertificateVerifier certificateVerifier;

	/** The TokenExtractionStrategy */
	private TokenExtractionStrategy tokenExtractionStrategy = TokenExtractionStrategy.NONE;
	
	/**
	 * Locale to use for reports generation
	 * By default a Locale from OS is used
	 */
	private Locale locale = Locale.getDefault();

	/** The CertificateProcessExecutor */
	private CertificateProcessExecutor processExecutor;

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
	 * Validates the certificate with a default validation policy
	 *
	 * @return {@link CertificateReports}
	 */
	public CertificateReports validate() {
		ValidationPolicy defaultPolicy = null;
		try {
			defaultPolicy = ValidationPolicyFacade.newFacade().getDefaultValidationPolicy();
		} catch (Exception e) {
			throw new DSSException("Unable to load the default policy", e);
		}
		return validate(defaultPolicy);
	}

	/**
	 * Validated the certificate with a custom validation policy
	 *
	 * @param validationPolicy {@link ValidationPolicy}
	 * @return {@link CertificateReports}
	 */
	public CertificateReports validate(ValidationPolicy validationPolicy) {
		SignatureValidationContext svc = new SignatureValidationContext();
		svc.initialize(certificateVerifier);
		svc.addCertificateTokenForVerification(token);
		svc.setCurrentTime(getValidationTime());
		svc.validate();

		final XmlDiagnosticData diagnosticData = new CertificateDiagnosticDataBuilder()
				.usedCertificates(svc.getProcessedCertificates())
				.usedRevocations(svc.getProcessedRevocations())
				.defaultDigestAlgorithm(certificateVerifier.getDefaultDigestAlgorithm())
				.tokenExtractionStrategy(tokenExtractionStrategy)
				.certificateSourceTypes(svc.getCertificateSourceTypes())
				.trustedCertificateSources(certificateVerifier.getTrustedCertSources())
				.validationDate(getValidationTime()).build();

		CertificateProcessExecutor executor = provideProcessExecutorInstance();
		executor.setValidationPolicy(validationPolicy);
		executor.setDiagnosticData(diagnosticData);
		executor.setCertificateId(token.getDSSIdAsString());
		executor.setLocale(locale);
		executor.setCurrentTime(getValidationTime());
		return executor.execute();
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
