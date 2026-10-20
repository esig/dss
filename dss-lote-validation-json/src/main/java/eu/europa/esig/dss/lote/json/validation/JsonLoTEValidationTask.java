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
package eu.europa.esig.dss.lote.json.validation;

import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.enumerations.TokenExtractionStrategy;
import eu.europa.esig.dss.enumerations.ValidationLevel;
import eu.europa.esig.dss.jades.validation.JWSCompactDocumentValidator;
import eu.europa.esig.dss.lote.validation.LoTEValidationResult;
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
import eu.europa.esig.dss.validation.job.validation.ValidationTask;
import eu.europa.esig.dss.validation.policy.ValidationPolicyLoader;
import eu.europa.esig.dss.validation.reports.Reports;

import java.util.Date;
import java.util.Objects;

/**
 * This class is used to validate a TS 119 602 JSON List of Trusted Entities
 * 
 */
public class JsonLoTEValidationTask implements ValidationTask {

    /** The path for a LoTE validation policy */
    // TODO : to be removed after DSS 6.6.
    private static final String LoTE_VALIDATION_POLICY_LOCATION = "/policy/te-json-constraint.xml";

    /** The LoTE document to validate */
    private final DSSDocument loteDocument;

    /** The certificate source to use */
    private final CertificateSource signingCertificateSource;

    /** Validation policy constraints */
    private ValidationPolicy validationPolicy;

    /**
     * Constructor used to instantiate a validator for a LoTE
     *
     * @param loteDocument      the DSSDocument with a LoTE
     * @param signingCertificateSource a certificate source with the allowed certificates to sign this LoTE
     * @deprecated since DSS 6.6. Please use
     *             {@link JsonLoTEValidationTask(DSSDocument, CertificateSource, ValidationPolicy)} instead.
     */
    @Deprecated
    public JsonLoTEValidationTask(DSSDocument loteDocument, CertificateSource signingCertificateSource) {
        Objects.requireNonNull(loteDocument, "The document is null");
        Objects.requireNonNull(signingCertificateSource, "The certificate source is null");
        this.loteDocument = loteDocument;
        this.signingCertificateSource = signingCertificateSource;
    }

    /**
     * Constructor used to instantiate a validator for a LoTE
     *
     * @param loteDocument      the DSSDocument with a LoTE
     * @param signingCertificateSource a certificate source with the allowed certificates to sign this LoTE
     * @param validationPolicy         validation policy constraint for LoTE validation
     */
    public JsonLoTEValidationTask(DSSDocument loteDocument, CertificateSource signingCertificateSource,
                                  ValidationPolicy validationPolicy) {
        Objects.requireNonNull(loteDocument, "The document is null");
        Objects.requireNonNull(signingCertificateSource, "The certificate source is null");
        this.loteDocument = loteDocument;
        this.signingCertificateSource = signingCertificateSource;
        this.validationPolicy = validationPolicy;
    }

    @Override
    public LoTEValidationResult get() {
        Reports reports = validate();
        return fillResult(reports);
    }

    private Reports validate() {
        final CertificateVerifier certificateVerifier = new CommonCertificateVerifier(true);
        certificateVerifier.setTrustedCertSources(buildTrustedCertificateSource(signingCertificateSource));

        final JWSCompactDocumentValidator jwsCompactDocumentValidator = new JWSCompactDocumentValidator(loteDocument);

        jwsCompactDocumentValidator.setCertificateVerifier(certificateVerifier);
        jwsCompactDocumentValidator.setTokenExtractionStrategy(TokenExtractionStrategy.EXTRACT_CERTIFICATES_ONLY);
        jwsCompactDocumentValidator.setEnableEtsiValidationReport(false); // Ignore ETSI VR
        jwsCompactDocumentValidator.setValidationLevel(ValidationLevel.BASIC_SIGNATURES); // Timestamps,... are ignored
        jwsCompactDocumentValidator.setValidationContextExecutor(SkipValidationContextExecutor.INSTANCE); // Only need to validate against the trusted certificate source
        jwsCompactDocumentValidator.setSignaturePolicyProvider(new SignaturePolicyProvider()); // ignore signature policy loading

        return jwsCompactDocumentValidator.validateDocument(getValidationPolicy());
    }

    private LoTEValidationResult fillResult(Reports reports) {
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

        return new LoTEValidationResult(indication, subIndication, signingTime, signingCertificate, signingCertificateSource);
    }

    private TrustedCertificateSource buildTrustedCertificateSource(CertificateSource certificateSource) {
        CommonTrustedCertificateSource commonTrustedCertificateSource = new CommonTrustedCertificateSource();
        commonTrustedCertificateSource.importAsTrusted(certificateSource);
        return commonTrustedCertificateSource;
    }

    private ValidationPolicy getValidationPolicy() {
        // TODO : after DSS 6.6, remove default instantiation
        if (validationPolicy == null) {
            try {
                validationPolicy = ValidationPolicyLoader.fromValidationPolicy(
                        JsonLoTEValidationTask.class.getResourceAsStream(LoTE_VALIDATION_POLICY_LOCATION)).create();
            } catch (Exception e) {
                throw new DSSException("Unable to load the validation policy for LoTE", e);
            }
        }
        return validationPolicy;
    }

}
