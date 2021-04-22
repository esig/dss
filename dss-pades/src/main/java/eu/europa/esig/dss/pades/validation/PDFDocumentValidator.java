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

import eu.europa.esig.dss.enumerations.TimestampedObjectType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.x509.revocation.crl.CRL;
import eu.europa.esig.dss.model.x509.revocation.ocsp.OCSP;
import eu.europa.esig.dss.pades.PAdESUtils;
import eu.europa.esig.dss.pades.validation.scope.PAdESSignatureScopeFinder;
import eu.europa.esig.dss.pades.validation.timestamp.PdfRevisionTimestampSource;
import eu.europa.esig.dss.pdf.IPdfObjFactory;
import eu.europa.esig.dss.pdf.PDFSignatureService;
import eu.europa.esig.dss.pdf.PdfDocDssRevision;
import eu.europa.esig.dss.pdf.PdfDocTimestampRevision;
import eu.europa.esig.dss.pdf.PdfDssDict;
import eu.europa.esig.dss.pdf.PdfSignatureRevision;
import eu.europa.esig.dss.pdf.ServiceLoaderPdfObjFactory;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.ListRevocationSource;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.ValidationContext;
import eu.europa.esig.dss.validation.scope.SignatureScope;
import eu.europa.esig.dss.validation.timestamp.TimestampToken;
import eu.europa.esig.dss.validation.timestamp.TimestampedReference;

import java.util.ArrayList;
import java.util.Arrays;
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
    private String passwordProtection;

    /**
     * Empty constructor
     */
    PDFDocumentValidator() {
    }

    /**
     * The default constructor for PDFDocumentValidator.
     *
     * @param document {@link DSSDocument}
     */
    public PDFDocumentValidator(final DSSDocument document) {
        super(new PAdESSignatureScopeFinder());
        if (!isSupported(document)) {
            throw new DSSException("Not supported document");
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
     * @param pwd the used password
     */
    public void setPasswordProtection(String pwd) {
        this.passwordProtection = pwd;
    }

    @Override
    protected ValidationContext prepareValidationContext(Collection<AdvancedSignature> signatures, Collection<TimestampToken> detachedTimestamps) {
        ValidationContext validationContext = super.prepareValidationContext(signatures, detachedTimestamps);
        List<PdfDssDict> dssDictionaries = getDssDictionaries();
        prepareDssDictionaryValidationContext(validationContext, dssDictionaries);
        return validationContext;
    }

    @Override
    protected PAdESDiagnosticDataBuilder initializeDiagnosticDataBuilder() {
        return new PAdESDiagnosticDataBuilder();
    }

    @Override
    protected ListRevocationSource<CRL> mergeCRLSources(Collection<AdvancedSignature> allSignatures,
                                                        Collection<TimestampToken> timestampTokens) {
        ListRevocationSource<CRL> listCRLSource = super.mergeCRLSources(allSignatures, timestampTokens);

        List<PdfDssDict> dssDictionaries = getDssDictionaries();
        if (Utils.isCollectionNotEmpty(dssDictionaries)) {
            for (PdfDssDict dssDictionary : dssDictionaries) {
                listCRLSource.add(new PdfDssDictCRLSource(dssDictionary));
            }
        }
        return listCRLSource;
    }

    @Override
    protected ListRevocationSource<OCSP> mergeOCSPSources(Collection<AdvancedSignature> allSignatures,
                                                          Collection<TimestampToken> timestampTokens) {
        ListRevocationSource<OCSP> listOCSPSource = super.mergeOCSPSources(allSignatures, timestampTokens);

        List<PdfDssDict> dssDictionaries = getDssDictionaries();
        if (Utils.isCollectionNotEmpty(dssDictionaries)) {
            for (PdfDssDict dssDictionary : dssDictionaries) {
                listOCSPSource.add(new PdfDssDictOCSPSource(dssDictionary));
            }
        }
        return listOCSPSource;
    }

    /**
     * Fills the {@code validateContext} with certificate tokens from {@code dssDicts}
     *
     * @param validationContext {@link ValidationContext} to enrich
     * @param dssDicts a list of {@link PdfDssDict}s
     */
    protected void prepareDssDictionaryValidationContext(final ValidationContext validationContext, List<PdfDssDict> dssDicts) {
        for (PdfDssDict dssDict : dssDicts) {
            validationContext.addDocumentCertificateSource(new PdfDssDictCertificateSource(dssDict));
            validationContext.addDocumentCRLSource(new PdfDssDictCRLSource(dssDict));
            validationContext.addDocumentOCSPSource(new PdfDssDictOCSPSource(dssDict));
        }
    }

    @Override
    public List<AdvancedSignature> getSignatures() {
        final List<AdvancedSignature> signatures = new ArrayList<>();

        for (PdfRevision pdfRevision : getRevisions()) {
            if (pdfRevision instanceof PdfSignatureRevision) {
                PdfSignatureRevision pdfSignatureRevision = (PdfSignatureRevision) pdfRevision;
                try {
                    final PAdESSignature padesSignature = new PAdESSignature(pdfSignatureRevision, documentRevisions);
                    padesSignature.setSignatureFilename(document.getName());
                    padesSignature.setSigningCertificateSource(signingCertificateSource);
                    padesSignature.prepareOfflineCertificateVerifier(certificateVerifier);
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
    public List<TimestampToken> getDetachedTimestamps() {
        final List<TimestampToken> timestamps = new ArrayList<>();
        final List<TimestampedReference> coveredReferences = new ArrayList<>();

        for (PdfRevision pdfRevision : Utils.reverseList(getRevisions())) {
            if (pdfRevision instanceof PdfDocTimestampRevision) {
                PdfDocTimestampRevision pdfDocTimestampRevision = (PdfDocTimestampRevision) pdfRevision;
                TimestampToken timestampToken = createPdfTimestampToken(pdfDocTimestampRevision);
                DSSUtils.enrichCollection(timestampToken.getTimestampedReferences(), coveredReferences);
                timestamps.add(timestampToken);

            } else if (pdfRevision instanceof PdfSignatureRevision) {
                break;
            }
            // returns refs for timestamps and DSS dictionaries
            PdfRevisionTimestampSource pdfRevisionTimestampSource = new PdfRevisionTimestampSource(pdfRevision);
            coveredReferences.addAll(pdfRevisionTimestampSource.getIncorporatedReferences());
        }
        return timestamps;
    }

    private TimestampToken createPdfTimestampToken(PdfDocTimestampRevision pdfDocTimestampRevision) {
        try {
            TimestampToken timestampToken = pdfDocTimestampRevision.getTimestampToken();
            timestampToken.setFileName(document.getName());

            PAdESSignatureScopeFinder signatureScopeFinder = new PAdESSignatureScopeFinder();
            signatureScopeFinder.setDefaultDigestAlgorithm(getDefaultDigestAlgorithm());
            SignatureScope signatureScope = signatureScopeFinder.findSignatureScope(pdfDocTimestampRevision);
            timestampToken.setTimestampScopes(Arrays.asList(signatureScope));
            timestampToken.getTimestampedReferences().add(
                    new TimestampedReference(signatureScope.getDSSIdAsString(), TimestampedObjectType.SIGNED_DATA));

            return timestampToken;

        } catch (Exception e) {
            throw new DSSException(String.format("Unable to create a timestamp for a revision : %s. Reason : [%s]",
                    pdfDocTimestampRevision.getByteRange(), e.getMessage()), e);
        }
    }

    /**
     * Returns a list of found DSS Dictionaries across different revisions
     *
     * @return list of {@link PdfDssDict}s
     */
    public List<PdfDssDict> getDssDictionaries() {
        List<PdfDssDict> docDssRevisions = new ArrayList<>();

        for (PdfRevision pdfRevision : getRevisions()) {
            if (pdfRevision instanceof PdfDocDssRevision) {
                PdfDocDssRevision dssRevision = (PdfDocDssRevision) pdfRevision;
                docDssRevisions.add(dssRevision.getDssDictionary());
            }
        }
        return Utils.reverseList(docDssRevisions);
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
    public List<DSSDocument> getOriginalDocuments(AdvancedSignature advancedSignature) {
        PAdESSignature padesSignature = (PAdESSignature) advancedSignature;
        List<DSSDocument> result = new ArrayList<>();
        InMemoryDocument originalPDF = PAdESUtils.getOriginalPDF(padesSignature);
        if (originalPDF != null) {
            result.add(originalPDF);
        }
        return result;
    }

}
