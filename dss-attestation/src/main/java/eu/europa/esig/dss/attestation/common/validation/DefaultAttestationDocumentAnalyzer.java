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
package eu.europa.esig.dss.attestation.common.validation;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.spi.attestation.Attestation;
import eu.europa.esig.dss.spi.attestation.AttestationPresentation;
import eu.europa.esig.dss.spi.attestation.AttestationValidationParameters;
import eu.europa.esig.dss.spi.attestation.revocation.AttestationRevocationSource;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.spi.validation.ValidationContext;
import eu.europa.esig.dss.spi.validation.analyzer.DefaultDocumentAnalyzer;
import eu.europa.esig.dss.spi.validation.analyzer.attestation.AttestationDocumentAnalyzer;
import eu.europa.esig.dss.spi.validation.analyzer.attestation.AttestationDocumentAnalyzerFactory;
import eu.europa.esig.dss.spi.x509.evidencerecord.EvidenceRecord;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Objects;

/**
 * Abstract class containing common code for validation of attestation presentation.
 * This class can be used as the first point of the attestation presentation validation.
 *
 */
public abstract class DefaultAttestationDocumentAnalyzer extends DefaultDocumentAnalyzer implements AttestationDocumentAnalyzer {

    /** Cached presentation of attestation */
    private AttestationPresentation attestationPresentation;

    /** Source used to verify revocation of the attestation */
    private AttestationRevocationSource attestationRevocationSource;

    /** Supplementary validation data */
    private AttestationValidationParameters attestationValidationParameters;

    /**
     * Empty constructor
     */
    protected DefaultAttestationDocumentAnalyzer() {
        // empty
    }

    /**
     * Instantiates the class with a document to be validated
     *
     * @param document {@link DSSDocument} to be validated
     */
    protected DefaultAttestationDocumentAnalyzer(DSSDocument document) {
        Objects.requireNonNull(document, "Document to be validated cannot be null!");
        this.document = document;
    }

    /**
     * This method guesses the document format and returns an appropriate attestation presentation reader.
     *
     * @param dssDocument
     *            The instance of {@code DSSDocument} to validate
     * @return returns the specific instance of {@link AttestationDocumentAnalyzer} in terms of the document type
     */
    public static AttestationDocumentAnalyzer fromDocument(final DSSDocument dssDocument) {
        return AttestationDocumentAnalyzerFactory.fromDocument(dssDocument);
    }

    @Override
    public AttestationPresentation getAttestationPresentation() {
        if (attestationPresentation == null) {
            attestationPresentation = buildAttestationPresentation();
            // TODO : scopes ?
        }
        return attestationPresentation;
    }

    /**
     * Sets the attestation revocation source providing access to the information about the attestation validity revocation
     *
     * @param attestationRevocationSource {@link AttestationRevocationSource}
     */
    public void setAttestationRevocationSource(AttestationRevocationSource attestationRevocationSource) {
        this.attestationRevocationSource = attestationRevocationSource;
    }

    /**
     * Gets supplementary validation parameters
     *
     * @return {@link AttestationValidationParameters}
     */
    protected AttestationValidationParameters getAttestationValidationParameters() {
        return attestationValidationParameters;
    }

    /**
     * Sets supplementary data parameters requiring for validation of the Attestation Presentation
     *
     * @param attestationValidationParameters {@link AttestationValidationParameters}
     */
    public void setAttestationValidationParameters(AttestationValidationParameters attestationValidationParameters) {
        this.attestationValidationParameters = attestationValidationParameters;
    }

    /**
     * Builds a presentation of attestation
     *
     * @return {@link AttestationPresentation}
     */
    protected abstract AttestationPresentation buildAttestationPresentation();

    @Override
    protected List<AdvancedSignature> buildSignatures() {
        AttestationPresentation presentation = getAttestationPresentation();

        final List<AdvancedSignature> result = new ArrayList<>();
        for (Attestation attestation : presentation.getAttestations()) {
            result.addAll(attestation.getSignatures());
            if (attestation.getKeyBindingSignature() != null) {
                result.add(attestation.getKeyBindingSignature());
            }
        }
        return result;
    }

    @Override
    protected <T extends AdvancedSignature> ValidationContext prepareValidationContext(
            Collection<T> signatures, Collection<TimestampToken> detachedTimestamps,
            Collection<EvidenceRecord> detachedEvidenceRecords, CertificateVerifier certificateVerifier) {
        AttestationValidationContext validationContext = (AttestationValidationContext) super.prepareValidationContext(signatures, detachedTimestamps, detachedEvidenceRecords, certificateVerifier);
        validationContext.setAttestationRevocationSource(attestationRevocationSource);

        AttestationPresentation attestationPresentation = getAttestationPresentation();
        prepareAttestationPresentationValidationContext(validationContext, attestationPresentation);
        return validationContext;
    }

    @Override
    protected ValidationContext createValidationContext() {
        return new AttestationValidationContext(getValidationTime());
    }

    /**
     * Prepares the {@code attestationValidationContext} for attestation validation process
     *
     * @param validationContext
     *                          {@link AttestationValidationContext}
     * @param attestationPresentation
     *                          {@link AttestationPresentation} to be validated
     */
    protected void prepareAttestationPresentationValidationContext(
            final AttestationValidationContext validationContext, final AttestationPresentation attestationPresentation) {
        prepareAttestationPresentationForVerification(validationContext, attestationPresentation);
        processAttestationPresentationValidation(attestationPresentation);
    }

    /**
     * This method prepares a {@code attestationValidationContext} for attestation presentation validation
     *
     * @param validationContext {@code attestationValidationContext}
     * @param attestationPresentation {@link AttestationPresentation}
     */
    protected void prepareAttestationPresentationForVerification(
            final AttestationValidationContext validationContext, final AttestationPresentation attestationPresentation) {
        validationContext.addAttestationPresentationForVerification(attestationPresentation);
    }

    /**
     * Performs cryptographic validation of the attestation signatures
     *
     * @param attestationPresentation {@link AttestationPresentation}
     */
    protected void processAttestationPresentationValidation(AttestationPresentation attestationPresentation) {
        for (final Attestation attestation : attestationPresentation.getAttestations()) {
            processSignaturesValidation(attestation.getSignatures());
            processSignatureValidation(attestation.getKeyBindingSignature());
        }
    }

    @Override
    public List<DSSDocument> getOriginalDocuments(String signatureId) {
        throw new UnsupportedOperationException("getOriginalDocuments(String signatureId) is " +
                "not supported for DefaultAttestationPresentationAnalyzer!");
    }

    @Override
    public List<DSSDocument> getOriginalDocuments(AdvancedSignature advancedSignature) {
        throw new UnsupportedOperationException("getOriginalDocuments(AdvancedSignature advancedSignature) is " +
                "not supported for DefaultAttestationPresentationAnalyzer!");
    }

}
