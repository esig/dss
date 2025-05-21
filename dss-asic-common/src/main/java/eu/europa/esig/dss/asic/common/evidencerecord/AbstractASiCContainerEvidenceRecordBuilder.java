package eu.europa.esig.dss.asic.common.evidencerecord;

import eu.europa.esig.dss.asic.common.ASiCContent;
import eu.europa.esig.dss.asic.common.ASiCEvidenceRecordFilenameFactory;
import eu.europa.esig.dss.asic.common.ASiCParameters;
import eu.europa.esig.dss.asic.common.ASiCUtils;
import eu.europa.esig.dss.asic.common.signature.AbstractASiCContentBuilder;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.enumerations.EvidenceRecordOrigin;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.ReferenceValidation;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.exception.IllegalInputException;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.spi.validation.SignatureValidationAlerter;
import eu.europa.esig.dss.spi.validation.SignatureValidationContext;
import eu.europa.esig.dss.spi.validation.analyzer.evidencerecord.EvidenceRecordAnalyzer;
import eu.europa.esig.dss.spi.validation.analyzer.evidencerecord.EvidenceRecordAnalyzerFactory;
import eu.europa.esig.dss.spi.x509.evidencerecord.EvidenceRecord;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;
import eu.europa.esig.dss.utils.Utils;

import java.util.ArrayList;
import java.util.List;

/**
 * Incorporates an existing evidence record document within an ASiC container
 *
 */
public abstract class AbstractASiCContainerEvidenceRecordBuilder {

    /** Used to verify the evidence record against the provided data */
    private final CertificateVerifier certificateVerifier;

    /** Filename factory */
    private final ASiCEvidenceRecordFilenameFactory asicFilenameFactory;

    /**
     * Default constructor
     *
     * @param certificateVerifier {@link CertificateVerifier}
     * @param asicFilenameFactory {@link ASiCEvidenceRecordFilenameFactory}
     */
    protected AbstractASiCContainerEvidenceRecordBuilder(final CertificateVerifier certificateVerifier,
                                                         final ASiCEvidenceRecordFilenameFactory asicFilenameFactory) {
        this.certificateVerifier = certificateVerifier;
        this.asicFilenameFactory = asicFilenameFactory;
    }

    /**
     * Builds an {@code ASiCContent} containing the evidence record file document
     *
     * @param documents a list of {@link DSSDocument}s to be preserved or an ASiC container
     * @param evidenceRecordDocument {@link DSSDocument} containing an evidence record to be added in ASiC container
     * @param parameters parameters used for container creation
     * @return {@link ASiCContent}
     */
    public ASiCContent build(List<DSSDocument> documents, DSSDocument evidenceRecordDocument, ASiCParameters parameters) {
        ASiCContent asicContent = initASiCContent(documents, parameters);
        assertASiCContentValid(asicContent, parameters);

        EvidenceRecord evidenceRecord = getEvidenceRecord(evidenceRecordDocument, asicContent);
        assertEvidenceRecordValid(evidenceRecord);

        List<DSSDocument> coveredDocuments = getDocumentsCoveredByEvidenceRecord(evidenceRecord, asicContent);
        assertSignedDataCovered(asicContent, coveredDocuments);

        String evidenceRecordFilename = asicFilenameFactory.getEvidenceRecordFilename(asicContent, evidenceRecord.getEvidenceRecordType());
        evidenceRecordDocument.setName(evidenceRecordFilename);
        asicContent.getEvidenceRecordDocuments().add(evidenceRecordDocument);

        DSSDocument evidenceRecordManifest = buildEvidenceRecordManifest(
                asicContent, coveredDocuments, evidenceRecord.getOriginalDigestAlgorithm(), evidenceRecordFilename);
        if (evidenceRecordManifest != null) {
            asicContent.getEvidenceRecordManifestDocuments().add(evidenceRecordManifest);
        }
        
        return ASiCUtils.ensureMimeTypeAndZipComment(asicContent, parameters);
    }

    private ASiCContent initASiCContent(List<DSSDocument> documents, ASiCParameters parameters) {
        return getASiCContentBuilder().build(documents, parameters.getContainerType());
    }

    /**
     * Gets an instance of {@code AbstractASiCContentBuilder}
     *
     * @return {@link AbstractASiCContentBuilder}
     */
    protected abstract AbstractASiCContentBuilder getASiCContentBuilder();

    private EvidenceRecord getEvidenceRecord(DSSDocument evidenceRecordDocument, ASiCContent asicContent) {
        try {
            EvidenceRecordAnalyzer evidenceRecordAnalyzer = EvidenceRecordAnalyzerFactory.fromDocument(evidenceRecordDocument);
            evidenceRecordAnalyzer.setDetachedContents(asicContent.getAllDocuments());
            evidenceRecordAnalyzer.setEvidenceRecordOrigin(EvidenceRecordOrigin.CONTAINER);
            return evidenceRecordAnalyzer.getEvidenceRecord();
        } catch (Exception e) {
            throw new IllegalInputException(String.format(
                    "Unable to build evidence record document. Reason : %s", e.getMessage()));
        }
    }

    private List<DSSDocument> getDocumentsCoveredByEvidenceRecord(EvidenceRecord evidenceRecord, ASiCContent asicContent) {
        final List<DSSDocument> coveredDocuments = new ArrayList<>();
        List<DSSDocument> allDocuments = asicContent.getAllDocuments();
        List<String> allDocumentFilenames = DSSUtils.getDocumentNames(allDocuments);
        for (ReferenceValidation referenceValidation : evidenceRecord.getReferenceValidation()) {
            String documentName = referenceValidation.getDocumentName();
            if (allDocumentFilenames.contains(referenceValidation.getDocumentName())) {
                coveredDocuments.add(DSSUtils.getDocumentWithName(allDocuments, documentName));
            }
        }
        return coveredDocuments;
    }

    private DSSDocument buildEvidenceRecordManifest(ASiCContent asicContent, List<DSSDocument> coveredDocuments,
                                                    DigestAlgorithm digestAlgorithm, String evidenceRecordFilename) {
        if (ASiCContainerType.ASiC_E == asicContent.getContainerType()) {
            return new ASiCEvidenceRecordManifestBuilder(asicContent, digestAlgorithm, evidenceRecordFilename)
                    .setAsicContentDocumentFilter(ASiCContentDocumentFilterFactory.allowedFilenamesFilter(getDocumentNames(coveredDocuments)))
                    .setEvidenceRecordFilenameFactory(asicFilenameFactory)
                    .build();

        } else {
            // skip for ASiC-S
            return null;
        }
    }

    private String[] getDocumentNames(List<DSSDocument> coveredDocuments) {
        return DSSUtils.getDocumentNames(coveredDocuments).toArray(new String[0]);
    }

    private void assertASiCContentValid(ASiCContent asicContent, ASiCParameters parameters) {
        ASiCContainerType currentContainerType = asicContent.getContainerType();

        boolean asice = ASiCUtils.isASiCE(parameters);
        if (asice && ASiCContainerType.ASiC_E.equals(currentContainerType)) {
            // ok

        } else if (!asice && ASiCContainerType.ASiC_S.equals(currentContainerType)) {
            if (Utils.collectionSize(asicContent.getSignedDocuments()) != 1) {
                throw new IllegalArgumentException(
                        "Only one original document is expected for the ASiC-S container type! If required, " +
                                "please create a 'package.zip' and provide it directly as a parameter. " +
                                "Otherwise, please switch to the ASiC-E type.");
            }

        } else {
            throw new UnsupportedOperationException(
                    String.format("Original container type '%s' vs parameter : '%s'", currentContainerType,
                            parameters.getContainerType()));
        }
    }

    private void assertSignedDataCovered(ASiCContent asicContent, List<DSSDocument> coveredDocuments) {
        for (DSSDocument signedDocument : asicContent.getSignedDocuments()) {
            if (!coveredDocuments.contains(signedDocument)) {
                throw new IllegalInputException(String.format("The original document with name '%s' is not covered " +
                        "by the evidence record's data group!", signedDocument.getName()));
            }
        }
    }

    private void assertEvidenceRecordValid(EvidenceRecord evidenceRecord) {
        final String errorMessage = "The digest covered by the evidence record do not correspond to " +
                "the digest computed on the provided content!";
        boolean signedDataFound = false;
        for (ReferenceValidation referenceValidation : evidenceRecord.getReferenceValidation()) {
            if (DigestMatcherType.EVIDENCE_RECORD_ORPHAN_REFERENCE != referenceValidation.getType()) {
                if (!referenceValidation.isIntact()) {
                    throw new IllegalInputException(errorMessage);
                }
                signedDataFound = true;
            }
        }
        if (!signedDataFound) {
            throw new IllegalInputException(errorMessage);
        }
        validateTimestamps(evidenceRecord);
    }

    private void validateTimestamps(EvidenceRecord evidenceRecord) {
        SignatureValidationContext validationContext = new SignatureValidationContext();
        validationContext.initialize(certificateVerifier);

        validationContext.addDocumentCertificateSource(evidenceRecord.getCertificateSource());
        for (TimestampToken timestampToken : evidenceRecord.getTimestamps()) {
            validationContext.addTimestampTokenForVerification(timestampToken);
        }

        validationContext.validate();

        SignatureValidationAlerter signatureValidationAlerter = new SignatureValidationAlerter(validationContext);
        signatureValidationAlerter.assertAllTimestampsValid();
    }

}
