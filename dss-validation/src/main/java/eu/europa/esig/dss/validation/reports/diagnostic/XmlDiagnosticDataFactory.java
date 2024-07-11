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
package eu.europa.esig.dss.validation.reports.diagnostic;

import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.TokenExtractionStrategy;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.identifier.TokenIdentifierProvider;
import eu.europa.esig.dss.spi.validation.ValidationContext;

import java.util.Date;
import java.util.Objects;

/**
 * This class creates a {@code XmlDiagnosticData}
 *
 */
public class XmlDiagnosticDataFactory {

    /** The corresponding diagnostic data builder */
    private final SignedDocumentDiagnosticDataBuilder diagnosticDataBuilder;

    /** The document to be validated */
    private DSSDocument document;

    /** The validation time */
    private Date validationTime;

    /** The current validation context */
    private ValidationContext validationContext;

    /** The used default digest algorithm for tokens definition */
    private DigestAlgorithm defaultDigestAlgorithm;

    /** The token extraction strategy to be used (i.e. binaries vs digest) */
    private TokenExtractionStrategy tokenExtractionStrategy;

    /** The class to compute identifiers for tokens to be returned in the reports */
    private TokenIdentifierProvider tokenIdentifierProvider;

    /**
     * Default constructor
     *
     * @param diagnosticDataBuilder {@link SignedDocumentDiagnosticDataBuilder} corresponding to the given signature format
     */
    public XmlDiagnosticDataFactory(final SignedDocumentDiagnosticDataBuilder diagnosticDataBuilder) {
        Objects.requireNonNull(diagnosticDataBuilder, "SignedDocumentDiagnosticDataBuilder is null!");
        this.diagnosticDataBuilder = diagnosticDataBuilder;
    }

    /**
     * Sets original document to be validated
     *
     * @param document {@link DSSDocument}
     * @return {@link XmlDiagnosticDataFactory} this
     */
    public XmlDiagnosticDataFactory setDocument(DSSDocument document) {
        this.document = document;
        return this;
    }

    /**
     * Sets the validation time
     *
     * @param validationTime {@link Date}
     * @return {@link XmlDiagnosticDataFactory} this
     */
    public XmlDiagnosticDataFactory setValidationTime(Date validationTime) {
        this.validationTime = validationTime;
        return this;
    }

    /**
     * Sets the validation context
     *
     * @param validationContext {@link ValidationContext}
     * @return {@link XmlDiagnosticDataFactory} this
     */
    public XmlDiagnosticDataFactory setValidationContext(ValidationContext validationContext) {
        this.validationContext = validationContext;
        return this;
    }

    /**
     * Sets the digest algorithm to be used to compute references to the data objects
     *
     * @param defaultDigestAlgorithm {@link DigestAlgorithm}
     * @return {@link XmlDiagnosticDataFactory} this
     */
    public XmlDiagnosticDataFactory setDefaultDigestAlgorithm(DigestAlgorithm defaultDigestAlgorithm) {
        this.defaultDigestAlgorithm = defaultDigestAlgorithm;
        return this;
    }

    /**
     * Sets the token extraction strategy
     *
     * @param tokenExtractionStrategy {@link TokenExtractionStrategy}
     * @return {@link XmlDiagnosticDataFactory} this
     */
    public XmlDiagnosticDataFactory setTokenExtractionStrategy(TokenExtractionStrategy tokenExtractionStrategy) {
        this.tokenExtractionStrategy = tokenExtractionStrategy;
        return this;
    }

    /**
     * Sets the token identifier provider
     *
     * @param tokenIdentifierProvider {@link TokenIdentifierProvider}
     * @return {@link XmlDiagnosticDataFactory} this
     */
    public XmlDiagnosticDataFactory setTokenIdentifierProvider(TokenIdentifierProvider tokenIdentifierProvider) {
        this.tokenIdentifierProvider = tokenIdentifierProvider;
        return this;
    }

    /**
     * Creates a {@code XmlDiagnosticData}
     *
     * @return {@link XmlDiagnosticData}
     */
    public XmlDiagnosticData create() {
        return diagnosticDataBuilder
                .document(document)
                .validationDate(validationTime)
                .foundSignatures(validationContext.getProcessedSignatures())
                .usedTimestamps(validationContext.getProcessedTimestamps())
                .foundEvidenceRecords(validationContext.getProcessedEvidenceRecords())
                .allCertificateSources(validationContext.getAllCertificateSources())
                .documentCertificateSource(validationContext.getDocumentCertificateSource())
                .documentCRLSource(validationContext.getDocumentCRLSource())
                .documentOCSPSource(validationContext.getDocumentOCSPSource())
                .usedCertificates(validationContext.getProcessedCertificates())
                .usedRevocations(validationContext.getProcessedRevocations())
                .defaultDigestAlgorithm(defaultDigestAlgorithm)
                .tokenExtractionStrategy(tokenExtractionStrategy)
                .tokenIdentifierProvider(tokenIdentifierProvider)
                .build();
    }

}
