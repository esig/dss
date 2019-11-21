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
package eu.europa.esig.dss.validation.timestamp;

import java.io.IOException;
import java.util.Arrays;
import java.util.Date;
import java.util.Objects;

import org.bouncycastle.tsp.TSPException;

import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.policy.ValidationPolicy;
import eu.europa.esig.dss.policy.ValidationPolicyFacade;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.CertificatePool;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.DiagnosticDataBuilder;
import eu.europa.esig.dss.validation.ProcessExecutorProvider;
import eu.europa.esig.dss.validation.SignatureValidationContext;
import eu.europa.esig.dss.validation.ValidationContext;
import eu.europa.esig.dss.validation.executor.SignatureAndTimestampProcessExecutor;
import eu.europa.esig.dss.validation.executor.timestamp.DefaultTimestampProcessExecutor;
import eu.europa.esig.dss.validation.reports.Reports;

public class TimestampValidator implements ProcessExecutorProvider<SignatureAndTimestampProcessExecutor> {

	private Date validationTime = new Date();
	private CertificateVerifier certificateVerifier;
	private SignatureAndTimestampProcessExecutor processExecutor;
	protected CertificatePool validationCertPool;
	
	private final DSSDocument timestampFile;
	private final DSSDocument timestampedData;
	private final TimestampType timestampType;
	
	public TimestampValidator(final DSSDocument timestampFile, final DSSDocument timestampedData) {
		this(timestampFile, timestampedData, null);
	}
	
	public TimestampValidator(final DSSDocument timestampFile, final DSSDocument timestampedData, final TimestampType timestampType) {
		this.timestampFile = timestampFile;
		this.timestampedData = timestampedData;
		this.timestampType = timestampType;
	}

	/**
	 * Provides a {@code CertificateVerifier} to be used during the validation process.
	 *
	 * @param certificateVerifier
	 *            {@code CertificateVerifier}
	 */
	public void setCertificateVerifier(final CertificateVerifier certificateVerifier) {
		this.certificateVerifier = certificateVerifier;
		if (validationCertPool == null) {
			validationCertPool = certificateVerifier.createValidationPool();
		}
	}

	@Override
	public void setProcessExecutor(SignatureAndTimestampProcessExecutor processExecutor) {
		this.processExecutor = processExecutor;
	}

	private SignatureAndTimestampProcessExecutor provideProcessExecutorInstance() {
		if (processExecutor == null) {
			processExecutor = new DefaultTimestampProcessExecutor();
		}
		return processExecutor;
	}
	
	/**
	 * Allows to define a custom validation time
	 * @param validationTime {@link Date}
	 */
	public void setValidationTime(Date validationTime) {
		this.validationTime = validationTime;
	}
	
	/**
	 * Retrieves the time-stamp token
	 * 
	 * @return {@link TimestampToken} with a validated message imprint
	 */
	protected TimestampToken getTimestamp() {
		TimestampToken timestampToken;
		try {
			timestampToken = new TimestampToken(DSSUtils.toCMSSignedData(timestampFile), timestampType, validationCertPool);
		} catch (TSPException | IOException e) {
			throw new DSSException("Unable to parse timestamp", e);
		}
		timestampToken.setFileName(timestampFile.getName());
		timestampToken.matchData(DSSUtils.toByteArray(timestampedData));
		return timestampToken;
	}

	/**
	 * Validates the timestamp with a default validation policy
	 * @return {@link TimestampReports}
	 */
	public Reports validate() {
		ValidationPolicy defaultPolicy = null;
		try {
			defaultPolicy = ValidationPolicyFacade.newFacade().getDefaultValidationPolicy();
		} catch (Exception e) {
			throw new DSSException("Unable to load the default policy", e);
		}
		return validate(defaultPolicy);
	}

	/**
	 * Validates the timestamp with a custom validation policy'
	 * @param validationPolicy a custom {@link ValidationPolicy} to validate the timestamp with
	 * @return {@link TimestampReports}
	 */
	public Reports validate(final ValidationPolicy validationPolicy) {
		Objects.requireNonNull(certificateVerifier, "CertificateVerifier must be set");
		
		final ValidationContext validationContext = new SignatureValidationContext(validationCertPool);
		
		TimestampToken timestampToken = getTimestamp();
		validationContext.addTimestampTokenForVerification(timestampToken);
		CertificateToken issuer = validationCertPool.getIssuer(timestampToken);
		if (issuer != null) {
			validationContext.addCertificateTokenForVerification(issuer);
		}
		
		validationContext.setCurrentTime(validationTime);
		validationContext.initialize(certificateVerifier);
		validationContext.validate();
		
		final XmlDiagnosticData diagnosticData = new DiagnosticDataBuilder().document(timestampFile)
				.usedCertificates(validationContext.getProcessedCertificates()).usedRevocations(validationContext.getProcessedRevocations())
				.setExternalTimestamps(Arrays.asList(timestampToken))
				.setDefaultDigestAlgorithm(certificateVerifier.getDefaultDigestAlgorithm())
				.includeRawCertificateTokens(certificateVerifier.isIncludeCertificateTokenValues())
				.includeRawRevocationData(certificateVerifier.isIncludeCertificateRevocationValues())
				.includeRawTimestampTokens(certificateVerifier.isIncludeTimestampTokenValues())
				.certificateSourceTypes(validationContext.getCertificateSourceTypes())
				.trustedCertificateSources(certificateVerifier.getTrustedCertSources())
				.validationDate(validationTime).build();
		
		SignatureAndTimestampProcessExecutor executor = provideProcessExecutorInstance();
		executor.setValidationPolicy(validationPolicy);
		executor.setDiagnosticData(diagnosticData);
		executor.setCurrentTime(validationTime);
		
		return executor.execute();
	}

}
