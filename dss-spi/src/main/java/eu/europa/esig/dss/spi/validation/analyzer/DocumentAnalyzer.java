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
package eu.europa.esig.dss.spi.validation.analyzer;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.ManifestFile;
import eu.europa.esig.dss.model.identifier.TokenIdentifierProvider;
import eu.europa.esig.dss.spi.policy.SignaturePolicyProvider;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.spi.validation.ValidationContext;
import eu.europa.esig.dss.spi.validation.executor.ValidationContextExecutor;
import eu.europa.esig.dss.spi.validation.ValidationDataContainer;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.spi.x509.evidencerecord.EvidenceRecord;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;

import java.util.Collection;
import java.util.Date;
import java.util.List;

/**
 * This class performs processing of a signature document, including extraction of signature and timestamp tokens,
 * cryptographic validation, certificate chain building and revocation data validation.
 * The class works exclusively with JAVA objects, and does not include ETSI EN 319 102-1 validation process,
 * nor JAXB objects.
 *
 */
public interface DocumentAnalyzer {

    /**
     * Gets document to be validated
     *
     * @return {@link DSSDocument}
     */
    DSSDocument getDocument();

    /**
     * Retrieves the signatures found in the document
     *
     * @return a list of AdvancedSignatures for validation purposes
     */
    List<AdvancedSignature> getSignatures();

    /**
     * Retrieves the detached timestamps found in the document
     *
     * @return a list of TimestampToken for validation purposes
     */
    List<TimestampToken> getDetachedTimestamps();

    /**
     * Retrieves the detached evidence records found in the document
     *
     * @return a list of Evidence Records for validation purposes
     */
    List<EvidenceRecord> getDetachedEvidenceRecords();

    /**
     * Provides a {@code CertificateVerifier} to be used during the validation process.
     *
     * @param certificateVerifier
     *            {@code CertificateVerifier}
     */
    void setCertificateVerifier(final CertificateVerifier certificateVerifier);

    /**
     * This method sets {@code ValidationContextExecutor} for validation of the prepared {@code ValidationContext}
     * Default: {@code eu.europa.esig.dss.validation.executor.context.DefaultValidationContextExecutor}
     *          (performs basic validation of tokens, including certificate chain building and
     *          revocation data extraction, without processing of validity checks)
     *
     * @param validationContextExecutor {@link ValidationContextExecutor}
     */
    void setValidationContextExecutor(ValidationContextExecutor validationContextExecutor);

    /**
     * Gets TokenIdentifierProvider
     *
     * @return {@link TokenIdentifierProvider}
     */
    TokenIdentifierProvider getTokenIdentifierProvider();

    /**
     * Sets the TokenIdentifierProvider
     *
     * @param tokenIdentifierProvider {@link TokenIdentifierProvider}
     */
    void setTokenIdentifierProvider(TokenIdentifierProvider tokenIdentifierProvider);

    /**
     * Returns document validation time
     *
     * @return {@link Date}
     */
    Date getValidationTime();

    /**
     * Allows to define a custom validation time
     *
     * @param validationTime {@link Date}
     */
    void setValidationTime(Date validationTime);

    /**
     * Sets the {@code List} of {@code DSSDocument} containing the original contents to sign, for detached signature
     * scenarios.
     *
     * @param detachedContent
     *            the {@code List} of {@code DSSDocument} to set
     */
    void setDetachedContents(final List<DSSDocument> detachedContent);

    /**
     * Sets a {@code List} of {@code DSSDocument} containing the evidence record documents covering the signature document.
     *
     * @param detachedEvidenceRecordDocuments
     *            the {@code List} of {@code DSSDocument} to set
     */
    void setDetachedEvidenceRecordDocuments(final List<DSSDocument> detachedEvidenceRecordDocuments);

    /**
     * Sets the {@code List} of {@code DSSDocument} containing the original container content for ASiC-S signatures.
     *
     * @param archiveContents
     *            the {@code List} of {@code DSSDocument} to set
     */
    void setContainerContents(final List<DSSDocument> archiveContents);

    /**
     * Sets a related {@code ManifestFile} to the document to be validated.
     *
     * @param manifestFile
     *            a {@code ManifestFile} to set
     */
    void setManifestFile(final ManifestFile manifestFile);

    /**
     * Checks if the document is supported by the current validator
     *
     * @param dssDocument {@link DSSDocument} to check
     * @return TRUE if the document is supported, FALSE otherwise
     */
    boolean isSupported(DSSDocument dssDocument);

    /**
     * Set a certificate source which allows to find the signing certificate by kid
     * or certificate's digest
     *
     * @param certificateSource the certificate source
     */
    void setSigningCertificateSource(CertificateSource certificateSource);

    /**
     * This method allows to set a provider for Signature policies
     *
     * @param signaturePolicyProvider {@link SignaturePolicyProvider}
     */
    void setSignaturePolicyProvider(SignaturePolicyProvider signaturePolicyProvider);

    /**
     * This method returns the signed document(s) without their signature(s)
     *
     * @param signatureId
     *            the DSS ID of the signature to extract original signer data for
     * @return list of {@link DSSDocument}s
     */
    List<DSSDocument> getOriginalDocuments(final String signatureId);

    /**
     * This method returns the signed document(s) without their signature(s)
     *
     * @param advancedSignature
     *            {@link AdvancedSignature} to find signer documents for
     * @return list of {@link DSSDocument}s
     */
    List<DSSDocument> getOriginalDocuments(final AdvancedSignature advancedSignature);

    /**
     * Extracts a validation data for provided collection of signatures
     *
     * @param <T> {@link AdvancedSignature} implementation
     * @param signatures a collection of {@link AdvancedSignature}s
     * @return {@link ValidationDataContainer}
     */
    <T extends AdvancedSignature> ValidationDataContainer getValidationData(Collection<T> signatures);

    /**
     * Extracts a validation data for provided collection of signatures and/or timestamps
     *
     * @param <T> {@link AdvancedSignature} implementation
     * @param signatures a collection of {@link AdvancedSignature}s
     * @param detachedTimestamps a collection of detached {@link TimestampToken}s
     * @return {@link ValidationDataContainer}
     */
    <T extends AdvancedSignature> ValidationDataContainer getValidationData(Collection<T> signatures, Collection<TimestampToken> detachedTimestamps);

    /**
     * This method performs validation of the document
     *
     * @return {@link ValidationContext}
     */
    ValidationContext validate();

}
