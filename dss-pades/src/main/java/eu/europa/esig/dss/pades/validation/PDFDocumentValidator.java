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
package eu.europa.esig.dss.pades.validation;

import eu.europa.esig.dss.exception.IllegalInputException;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.scope.SignatureScope;
import eu.europa.esig.dss.model.x509.revocation.crl.CRL;
import eu.europa.esig.dss.model.x509.revocation.ocsp.OCSP;
import eu.europa.esig.dss.pades.PAdESUtils;
import eu.europa.esig.dss.pades.validation.scope.PAdESTimestampScopeFinder;
import eu.europa.esig.dss.pades.validation.timestamp.PdfRevisionTimestampSource;
import eu.europa.esig.dss.pades.validation.timestamp.PdfTimestampToken;
import eu.europa.esig.dss.pdf.IPdfObjFactory;
import eu.europa.esig.dss.pdf.PDFSignatureService;
import eu.europa.esig.dss.pdf.PdfDocDssRevision;
import eu.europa.esig.dss.pdf.PdfDocTimestampRevision;
import eu.europa.esig.dss.pdf.PdfDssDict;
import eu.europa.esig.dss.pdf.PdfSignatureRevision;
import eu.europa.esig.dss.pdf.ServiceLoaderPdfObjFactory;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.ListCertificateSource;
import eu.europa.esig.dss.spi.x509.evidencerecord.EvidenceRecord;
import eu.europa.esig.dss.spi.x509.revocation.ListRevocationSource;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;
import eu.europa.esig.dss.spi.x509.tsp.TimestampedReference;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.ValidationContext;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Objects;

/**
 * Validation of PDF document.
 */
public class PDFDocumentValidator extends SignedDocumentValidator {

    /** Loads the relevant implementation for PDF document reading */
    private IPdfObjFactory pdfObjectFactory = new ServiceLoaderPdfObjFactory();

    /** List of PDF document revisions */
    private List<PdfRevision> documentRevisions;

    /** The PDF document password (for protected documents) */
    private char[] passwordProtection;

    /**
     * Empty constructor
     */
    protected PDFDocumentValidator() {
        // empty
    }

    /**
     * The default constructor for PDFDocumentValidator.
     *
     * @param document {@link DSSDocument}
     */
    public PDFDocumentValidator(final DSSDocument document) {
        Objects.requireNonNull(document, "Document to be validated cannot be null!");

        if (!isSupported(document)) {
            throw new IllegalInputException("Not supported document");
        }
        this.document = document;
    }

    @Override
    public boolean isSupported(DSSDocument dssDocument) {
        return PAdESUtils.isPDFDocument(dssDocument);
    }

    /**
     * Set the IPdfObjFactory. Allow to set the used implementation. Cannot be null.
     *
     * @param pdfObjFactory the implementation to be used.
     */
    public void setPdfObjFactory(IPdfObjFactory pdfObjFactory) {
        Objects.requireNonNull(pdfObjFactory, "PdfObjFactory is null");
        this.pdfObjectFactory = pdfObjFactory;
    }

    /**
     * Specify the used password for the encrypted document
     *
     * @param passwordProtection the used password
     */
    public void setPasswordProtection(char[] passwordProtection) {
        this.passwordProtection = passwordProtection;
    }

    @Override
    protected <T extends AdvancedSignature> ValidationContext prepareValidationContext(
            Collection<T> signatures, Collection<TimestampToken> detachedTimestamps, Collection<EvidenceRecord> detachedEvidenceRecords,
            CertificateVerifier certificateVerifier) {
        ValidationContext validationContext = super.prepareValidationContext(signatures, detachedTimestamps, detachedEvidenceRecords, certificateVerifier);
        List<PdfDocDssRevision> dssRevisions = getDssRevisions();
        prepareDssDictionaryValidationContext(validationContext, dssRevisions);
        return validationContext;
    }

    @Override
    protected PAdESDiagnosticDataBuilder initializeDiagnosticDataBuilder() {
        return new PAdESDiagnosticDataBuilder();
    }

    /**
     * Fills the {@code validateContext} with certificate tokens from {@code dssDicts}
     *
     * @param validationContext {@link ValidationContext} to enrich
     * @param dssRevisions a list of {@link PdfDocDssRevision}s
     */
    protected void prepareDssDictionaryValidationContext(final ValidationContext validationContext, List<PdfDocDssRevision> dssRevisions) {
        for (PdfDocDssRevision dssRevision : dssRevisions) {
            validationContext.addDocumentCertificateSource(dssRevision.getCertificateSource());
            validationContext.addDocumentCRLSource(dssRevision.getCRLSource());
            validationContext.addDocumentOCSPSource(dssRevision.getOCSPSource());
        }
    }

    @Override
    protected List<AdvancedSignature> getAllSignatures() {
        List<AdvancedSignature> allSignatures = super.getAllSignatures();
        postProcessing(allSignatures);
        return allSignatures;
    }

    /**
     * Post-process the extracted signatures
     * NOTE: the method shall be used only for the document validation
     *
     * @param signatures a list of {@link AdvancedSignature}s
     */
    protected void postProcessing(List<AdvancedSignature> signatures) {
        PDFSignatureService pdfSignatureService = pdfObjectFactory.newPAdESSignatureService();
        pdfSignatureService.analyzePdfModifications(document, signatures, passwordProtection);
    }

    @Override
    public List<TimestampToken> getDetachedTimestamps() {
        List<TimestampToken> detachedTimestamps = super.getDetachedTimestamps();
        timestampPostProcessing(detachedTimestamps);
        return detachedTimestamps;
    }

    /**
     * Post-process the extracted detached timestamps
     * NOTE: the method shall be used only for the document validation
     *
     * @param timestampTokens a list of {@link TimestampToken}s
     */
    protected void timestampPostProcessing(List<TimestampToken> timestampTokens) {
        PDFSignatureService pdfSignatureService = pdfObjectFactory.newPAdESSignatureService();
        pdfSignatureService.analyzeTimestampPdfModifications(document, timestampTokens, passwordProtection);
    }

    @Override
    protected List<AdvancedSignature> buildSignatures() {
        final List<AdvancedSignature> signatures = new ArrayList<>();

        final ListCertificateSource dssCertificateSource = new ListCertificateSource();
        final ListRevocationSource<CRL> dssCRLSource = new ListRevocationSource<>();
        final ListRevocationSource<OCSP> dssOCSPSource = new ListRevocationSource<>();

        for (PdfRevision pdfRevision : getRevisions()) {

            if (pdfRevision instanceof PdfDocDssRevision) {

                PdfDocDssRevision docDssRevision = (PdfDocDssRevision) pdfRevision;
                dssCertificateSource.add(docDssRevision.getCertificateSource());
                dssCRLSource.add(docDssRevision.getCRLSource());
                dssOCSPSource.add(docDssRevision.getOCSPSource());

            } else if (pdfRevision instanceof PdfSignatureRevision) {

                PdfSignatureRevision pdfSignatureRevision = (PdfSignatureRevision) pdfRevision;
                try {
                    final PAdESSignature padesSignature = new PAdESSignature(pdfSignatureRevision, documentRevisions);
                    padesSignature.setSignatureFilename(document.getName());
                    padesSignature.setSigningCertificateSource(signingCertificateSource);

                    ListCertificateSource listCertificateSource = new ListCertificateSource();
                    listCertificateSource.addAll(dssCertificateSource);
                    padesSignature.setDssCertificateSource(listCertificateSource);

                    ListRevocationSource<CRL> listCRLSource = new ListRevocationSource<>();
                    listCRLSource.addAll(dssCRLSource);
                    padesSignature.setDssCRLSource(listCRLSource);

                    ListRevocationSource<OCSP> listOCSPSource = new ListRevocationSource<>();
                    listOCSPSource.addAll(dssOCSPSource);
                    padesSignature.setDssOCSPSource(listOCSPSource);

                    if (certificateVerifier != null) {
                        padesSignature.prepareOfflineCertificateVerifier(certificateVerifier);
                    }

                    signatures.add(padesSignature);

                } catch (Exception e) {
                    throw new DSSException(
                            String.format("Unable to collect a signature. Reason : [%s]", e.getMessage()), e);
                }

            }
        }
        return Utils.reverseList(signatures);
    }

    @Override
    protected List<TimestampToken> buildDetachedTimestamps() {
        final List<TimestampToken> timestamps = new ArrayList<>();
        final List<TimestampedReference> coveredReferences = new ArrayList<>();

        final ListCertificateSource certificateSource = new ListCertificateSource();
        final ListRevocationSource<CRL> crlSource = new ListRevocationSource<>();
        final ListRevocationSource<OCSP> ocspSource = new ListRevocationSource<>();

        for (PdfRevision pdfRevision : Utils.reverseList(getRevisions())) {
            if (pdfRevision instanceof PdfDocTimestampRevision) {
                PdfDocTimestampRevision pdfDocTimestampRevision = (PdfDocTimestampRevision) pdfRevision;
                TimestampToken timestampToken = createPdfTimestampToken(pdfDocTimestampRevision);
                certificateSource.add(timestampToken.getCertificateSource());
                crlSource.add(timestampToken.getCRLSource());
                ocspSource.add(timestampToken.getOCSPSource());

                DSSUtils.enrichCollection(timestampToken.getTimestampedReferences(), coveredReferences);
                timestamps.add(timestampToken);

            } else if (pdfRevision instanceof PdfDocDssRevision) {
                PdfDocDssRevision pdfDocDssRevision = (PdfDocDssRevision) pdfRevision;
                certificateSource.add(pdfDocDssRevision.getCertificateSource());
                crlSource.add(pdfDocDssRevision.getCRLSource());
                ocspSource.add(pdfDocDssRevision.getOCSPSource());

            } else if (pdfRevision instanceof PdfSignatureRevision) {
                break;
            }

            // return refs for timestamps and DSS dictionaries
            PdfRevisionTimestampSource pdfRevisionTimestampSource = new PdfRevisionTimestampSource(
                    pdfRevision, certificateSource, crlSource, ocspSource);
            coveredReferences.addAll(pdfRevisionTimestampSource.getIncorporatedReferences());
        }
        return timestamps;
    }

    private TimestampToken createPdfTimestampToken(PdfDocTimestampRevision pdfDocTimestampRevision) {
        try {
            PdfTimestampToken timestampToken = pdfDocTimestampRevision.getTimestampToken();
            timestampToken.setFileName(document.getName());

            List<SignatureScope> timestampScopes = getPAdESTimestampScopeFinder().findTimestampScope(timestampToken);
            timestampToken.setTimestampScopes(timestampScopes);
            timestampToken.getTimestampedReferences().addAll(getTimestampedReferences(timestampScopes));
            appendExternalEvidenceRecords(timestampToken);

            return timestampToken;

        } catch (Exception e) {
            throw new DSSException(String.format("Unable to create a timestamp for a revision : %s. Reason : [%s]",
                    pdfDocTimestampRevision.getByteRange(), e.getMessage()), e);
        }
    }

    /**
     * This method returns a PDF timestamp scope finder
     *
     * @return {@link PAdESTimestampScopeFinder}
     */
    protected PAdESTimestampScopeFinder getPAdESTimestampScopeFinder() {
        return new PAdESTimestampScopeFinder();
    }

    /**
     * Returns a list of found DSS Dictionaries across different revisions
     *
     * @return list of {@link PdfDssDict}s
     */
    public List<PdfDssDict> getDssDictionaries() {
        List<PdfDssDict> dssDicts = new ArrayList<>();
        for (PdfDocDssRevision dssRevision : getDssRevisions()) {
            dssDicts.add(dssRevision.getDssDictionary());
        }
        return dssDicts;
    }

    /**
     * This method returns a list of DSS revisions
     *
     * @return a list of {@link PdfDocDssRevision}s
     */
    protected List<PdfDocDssRevision> getDssRevisions() {
        List<PdfDocDssRevision> dssRevisions = new ArrayList<>();

        for (PdfRevision pdfRevision : getRevisions()) {
            if (pdfRevision instanceof PdfDocDssRevision) {
                dssRevisions.add((PdfDocDssRevision) pdfRevision);
            }
        }
        return Utils.reverseList(dssRevisions);
    }

    /**
     * Gets the list of PDF document revisions
     *
     * @return a list of {@link PdfRevision}s
     */
    protected List<PdfRevision> getRevisions() {
        if (documentRevisions == null) {
            PDFSignatureService pdfSignatureService = pdfObjectFactory.newPAdESSignatureService();
            documentRevisions = pdfSignatureService.getRevisions(document, passwordProtection);
        }
        return documentRevisions;
    }

    @Override
    public <T extends AdvancedSignature> PdfValidationDataContainer getValidationData(
            Collection<T> signatures, Collection<TimestampToken> detachedTimestamps) {
        return (PdfValidationDataContainer) super.getValidationData(signatures, detachedTimestamps);
    }

    @Override
    protected PdfValidationDataContainer instantiateValidationDataContainer() {
        return new PdfValidationDataContainer(getDssRevisions());
    }

    @Override
    public List<DSSDocument> getOriginalDocuments(AdvancedSignature advancedSignature) {
        PAdESSignature padesSignature = (PAdESSignature) advancedSignature;
        List<DSSDocument> result = new ArrayList<>();
        DSSDocument originalPDF = PAdESUtils.getOriginalPDF(padesSignature);
        if (originalPDF != null && !DSSUtils.isEmpty(originalPDF)) {
            result.add(originalPDF);
        }
        return result;
    }

}
