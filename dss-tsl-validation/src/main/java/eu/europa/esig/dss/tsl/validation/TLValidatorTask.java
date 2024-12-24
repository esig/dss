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
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.policy.ValidationPolicy;
import eu.europa.esig.dss.policy.ValidationPolicyFacade;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.policy.SignaturePolicyProvider;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.spi.validation.executor.SkipValidationContextExecutor;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.spi.x509.TrustedCertificateSource;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.xades.definition.XAdESPath;
import eu.europa.esig.dss.xades.definition.xades132.XAdES132Path;
import eu.europa.esig.dss.xades.validation.XMLDocumentValidator;

import java.util.Date;
import java.util.List;
import java.util.Objects;
import java.util.function.Supplier;

/**
 * This class allows to validate TL or LOTL.
 */
public class TLValidatorTask implements Supplier<ValidationResult> {

	/** The Trusted List document to validate */
	private final DSSDocument trustedList;

	/** The certificate source to use */
	private final CertificateSource certificateSource;

	/**
	 * Constructor used to instantiate a validator for a trusted list
	 *
	 * @param trustedList       the DSSDocument with a trusted list
	 * @param certificateSource a certificate source with the allowed certificates
	 *                          to sign this TL
	 */
	public TLValidatorTask(DSSDocument trustedList, CertificateSource certificateSource) {
		Objects.requireNonNull(trustedList, "The document is null");
		Objects.requireNonNull(certificateSource, "The certificate source is null");
		this.trustedList = trustedList;
		this.certificateSource = certificateSource;
	}

	@Override
	public ValidationResult get() {
		Reports reports = validateTL();
		return fillResult(reports);
	}

	private Reports validateTL() {
		final CertificateVerifier certificateVerifier = new CommonCertificateVerifier(true);
		certificateVerifier.setTrustedCertSources(buildTrustedCertificateSource(certificateSource));

		final XMLDocumentValidator xmlDocumentValidator = new XMLDocumentValidator(trustedList);

		xmlDocumentValidator.setCertificateVerifier(certificateVerifier);
		xmlDocumentValidator.setTokenExtractionStrategy(TokenExtractionStrategy.EXTRACT_CERTIFICATES_ONLY);
		xmlDocumentValidator.setEnableEtsiValidationReport(false); // Ignore ETSI VR
		xmlDocumentValidator.setValidationLevel(ValidationLevel.BASIC_SIGNATURES); // Timestamps,... are ignored
		xmlDocumentValidator.setValidationContextExecutor(SkipValidationContextExecutor.INSTANCE); // Only need to validate against the trusted certificate source
		xmlDocumentValidator.setSignaturePolicyProvider(new SignaturePolicyProvider()); // ignore signature policy loading

		// To increase the security: the default {@code XAdESPaths} is used.
		List<XAdESPath> xadesPathsHolders = xmlDocumentValidator.getXAdESPathsHolder();
		xadesPathsHolders.clear();
		xadesPathsHolders.add(new XAdES132Path());

		return xmlDocumentValidator.validateDocument(getTrustedListValidationPolicy());
	}

	private ValidationResult fillResult(Reports reports) {
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

		return new ValidationResult(indication, subIndication, signingTime, signingCertificate, certificateSource);
	}

	private TrustedCertificateSource buildTrustedCertificateSource(CertificateSource certificateSource) {
		CommonTrustedCertificateSource commonTrustedCertificateSource = new CommonTrustedCertificateSource();
		commonTrustedCertificateSource.importAsTrusted(certificateSource);
		return commonTrustedCertificateSource;
	}

	private ValidationPolicy getTrustedListValidationPolicy() {
		try {
			return ValidationPolicyFacade.newFacade().getTrustedListValidationPolicy();
		} catch (Exception e) {
			throw new DSSException("Unable to load the validation policy for trusted list", e);
		}
	}

}
