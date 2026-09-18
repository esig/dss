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
package eu.europa.esig.dss.tsl.validation;

import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.enumerations.TokenExtractionStrategy;
import eu.europa.esig.dss.enumerations.ValidationLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.policy.ValidationPolicy;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.policy.SignaturePolicyProvider;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.spi.validation.executor.SkipValidationContextExecutor;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.spi.x509.TrustedCertificateSource;
import eu.europa.esig.dss.validation.job.validation.ValidationResult;
import eu.europa.esig.dss.validation.job.validation.ValidationTask;
import eu.europa.esig.dss.validation.policy.ValidationPolicyLoader;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.xades.definition.xades132.XAdES132Path;
import eu.europa.esig.dss.xades.validation.XMLDocumentValidator;

import java.util.Collections;
import java.util.Date;
import java.util.Objects;

/**
 * This class allows to validate TL or LOTL.
 */
public class TLValidatorTask implements ValidationTask {

	/** The path for a LOTL/TL validation policy */
	private static final String TRUSTED_LIST_VALIDATION_POLICY_LOCATION = "/policy/tsl-constraint.xml";

	/** The Trusted List document to validate */
	private final DSSDocument trustedList;

	/** The certificate source to use */
	private final CertificateSource certificateSource;

	/** Validation policy constraints */
	private ValidationPolicy validationPolicy;

	/**
	 * Constructor used to instantiate a validator for a trusted list
	 *
	 * @param trustedList       the DSSDocument with a trusted list
	 * @param certificateSource a certificate source with the allowed certificates
	 *                          to sign this TL
	 * @deprecated since DSS 6.6. To be removed
	 */
	@Deprecated
	public TLValidatorTask(DSSDocument trustedList, CertificateSource certificateSource) {
		this(trustedList, certificateSource, null);
	}

	/**
	 * Constructor used to instantiate a validator for a trusted list
	 *
	 * @param trustedList       the DSSDocument with a trusted list
	 * @param certificateSource a certificate source with the allowed certificates
	 *                          to sign this TL
	 * @param validationPolicy  validation policy constraints for TL validation
	 */
	public TLValidatorTask(DSSDocument trustedList, CertificateSource certificateSource,
						   ValidationPolicy validationPolicy) {
		Objects.requireNonNull(trustedList, "The document is null");
		Objects.requireNonNull(certificateSource, "The certificate source is null");
		this.trustedList = trustedList;
		this.certificateSource = certificateSource;
		this.validationPolicy = validationPolicy;
	}

	@Override
	public ValidationResult get() {
		Reports reports = validateTL();
		return fillResult(reports);
	}

	private Reports validateTL() {
		final CertificateVerifier certificateVerifier = new CommonCertificateVerifier(true);
		certificateVerifier.setTrustedCertSources(buildTrustedCertificateSource(certificateSource));

		// To increase the security: the default {@code XAdESPaths} is used.
		final XMLDocumentValidator xmlDocumentValidator = new XMLDocumentValidator(trustedList, Collections.singletonList(new XAdES132Path()));

		xmlDocumentValidator.setCertificateVerifier(certificateVerifier);
		xmlDocumentValidator.setTokenExtractionStrategy(TokenExtractionStrategy.EXTRACT_CERTIFICATES_ONLY);
		xmlDocumentValidator.setEnableEtsiValidationReport(false); // Ignore ETSI VR
		xmlDocumentValidator.setValidationLevel(ValidationLevel.BASIC_SIGNATURES); // Timestamps,... are ignored
		xmlDocumentValidator.setValidationContextExecutor(SkipValidationContextExecutor.INSTANCE); // Only need to validate against the trusted certificate source
		xmlDocumentValidator.setSignaturePolicyProvider(new SignaturePolicyProvider()); // ignore signature policy loading

		return xmlDocumentValidator.validateDocument(getTrustedListValidationPolicy());
	}

	private TLValidationResult fillResult(Reports reports) {
		SimpleReport simpleReport = reports.getSimpleReport();
		if (simpleReport.getSignaturesCount() != 1) {
			throw new DSSException(String.format("Number of signatures must be equal to 1 (currently : %s)", simpleReport.getSignaturesCount()));
		}

		Indication indication = simpleReport.getIndication(simpleReport.getFirstSignatureId());
		SubIndication subIndication = simpleReport.getSubIndication(simpleReport.getFirstSignatureId());

		DiagnosticData diagnosticData = reports.getDiagnosticData();
		SignatureWrapper signatureWrapper = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		Date signingTime = signatureWrapper.getClaimedSigningTime();
		CertificateWrapper signingCertificateWrapper = signatureWrapper.getSigningCertificate();
		CertificateToken signingCertificate = null;
		if (signingCertificateWrapper != null) {
			signingCertificate = DSSUtils.loadCertificate(signingCertificateWrapper.getBinaries());
		}

		return new TLValidationResult(indication, subIndication, signingTime, signingCertificate, certificateSource);
	}

	private TrustedCertificateSource buildTrustedCertificateSource(CertificateSource certificateSource) {
		CommonTrustedCertificateSource commonTrustedCertificateSource = new CommonTrustedCertificateSource();
		commonTrustedCertificateSource.importAsTrusted(certificateSource);
		return commonTrustedCertificateSource;
	}

	private ValidationPolicy getTrustedListValidationPolicy() {
		// TODO : after DSS 6.6, remove default instantiation
		if (validationPolicy == null) {
			try {
				validationPolicy = ValidationPolicyLoader.fromValidationPolicy(
						TLValidatorTask.class.getResourceAsStream(TRUSTED_LIST_VALIDATION_POLICY_LOCATION)).create();
			} catch (Exception e) {
				throw new DSSException("Unable to load the validation policy for trusted list", e);
			}
		}
		return validationPolicy;
	}

}
