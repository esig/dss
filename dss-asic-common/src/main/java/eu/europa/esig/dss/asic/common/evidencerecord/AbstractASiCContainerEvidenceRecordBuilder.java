package eu.europa.esig.dss.asic.common.evidencerecord;

import eu.europa.esig.dss.asic.common.ASiCContainerEvidenceRecordParameters;
import eu.europa.esig.dss.asic.common.ASiCContent;
import eu.europa.esig.dss.asic.common.ASiCEvidenceRecordFilenameFactory;
import eu.europa.esig.dss.asic.common.ASiCParameters;
import eu.europa.esig.dss.asic.common.ASiCUtils;
import eu.europa.esig.dss.asic.common.signature.AbstractASiCContentBuilder;
import eu.europa.esig.dss.asic.common.validation.ASiCManifestParser;
import eu.europa.esig.dss.asic.common.validation.ASiCManifestValidator;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.ASiCManifestTypeEnum;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.enumerations.EvidenceRecordOrigin;
import eu.europa.esig.dss.enumerations.EvidenceRecordTypeEnum;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.ManifestEntry;
import eu.europa.esig.dss.model.ManifestFile;
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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Incorporates an existing evidence record document within an ASiC container
 *
 */
public abstract class AbstractASiCContainerEvidenceRecordBuilder {

    private static final Logger LOG = LoggerFactory.getLogger(AbstractASiCContainerEvidenceRecordBuilder.class);

    /** Used to verify the evidence record against the provided data */
    protected final CertificateVerifier certificateVerifier;

    /** Filename factory */
    protected final ASiCEvidenceRecordFilenameFactory asicFilenameFactory;

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
     * @param parameters {@link ASiCContainerEvidenceRecordParameters} parameters used for container creation
     * @return {@link ASiCContent}
     */
    public ASiCContent build(List<DSSDocument> documents, DSSDocument evidenceRecordDocument, ASiCContainerEvidenceRecordParameters parameters) {
        ASiCContent asicContent = initASiCContent(documents, parameters);
        assertASiCContentValid(asicContent, parameters);

        DSSDocument evidenceRecordManifest = getASiCEvidenceRecordManifest(parameters);
        ManifestFile manifestFile = parseManifestFile(evidenceRecordManifest, asicContent); // may be null
        assertManifestFileValid(manifestFile, asicContent);

        EvidenceRecord evidenceRecord = getEvidenceRecord(evidenceRecordDocument, manifestFile, asicContent);
        assertEvidenceRecordValid(evidenceRecord, manifestFile);

        List<DSSDocument> coveredDocuments = getDocumentsCoveredByEvidenceRecord(evidenceRecord, asicContent);
        assertSignedDataCovered(asicContent, DSSUtils.getDocumentNames(coveredDocuments));

        String evidenceRecordFilename = getEvidenceRecordFilename(evidenceRecord, manifestFile, asicContent);
        assertEvidenceRecordFilenameValid(evidenceRecordFilename, evidenceRecord.getEvidenceRecordType(), asicContent);

        evidenceRecordDocument.setName(evidenceRecordFilename);
        asicContent.getEvidenceRecordDocuments().add(evidenceRecordDocument);

        if (evidenceRecordManifest == null) {
            evidenceRecordManifest = buildEvidenceRecordManifest(
                    asicContent, coveredDocuments, evidenceRecord.getOriginalDigestAlgorithm(), evidenceRecordFilename);
        }
        // NOTE: can be null (e.g. for ASiC-S)
        if (evidenceRecordManifest != null) {
            asicContent.getEvidenceRecordManifestDocuments().add(evidenceRecordManifest);
        }
        
        return ASiCUtils.ensureMimeTypeAndZipComment(asicContent, parameters);
    }

    /**
     * This method initializes an {@code ASiCContent} from the given list of {@code documents}
     *
     * @param documents a list of {@link DSSDocument}s to create an ASiC container from
     * @param parameters {@link ASiCParameters}
     * @return {@link ASiCContent}
     */
    protected ASiCContent initASiCContent(List<DSSDocument> documents, ASiCParameters parameters) {
        return getASiCContentBuilder().build(documents, parameters.getContainerType());
    }

    /**
     * Gets an instance of {@code AbstractASiCContentBuilder}
     *
     * @return {@link AbstractASiCContentBuilder}
     */
    protected abstract AbstractASiCContentBuilder getASiCContentBuilder();

    /**
     * Gets the provided ASiCEvidenceRecordManifest file
     *
     * @param parameters {@link ASiCContainerEvidenceRecordParameters}
     * @return {@link DSSDocument}
     */
    protected DSSDocument getASiCEvidenceRecordManifest(ASiCContainerEvidenceRecordParameters parameters) {
        if (parameters.getAsicEvidenceRecordManifest() != null) {
            if (ASiCContainerType.ASiC_E == parameters.getContainerType()) {
                return parameters.getAsicEvidenceRecordManifest();
            } else {
                LOG.info("ASiC-S container does not require an ASiCEvidenceRecordManifest file. The parameter is skipped.");
            }
        }
        return null;
    }

    /**
     * Creates an {@code EvidenceRecord} from a provided {@code evidenceRecordDocument}
     *
     * @param evidenceRecordDocument {@link DSSDocument} containing evidence record
     * @param manifestFile {@link ManifestFile} ASiCEvidenceRecordDocument applying to the evidence record, when present
     * @param asicContent {@link ASiCContent}
     * @return {@link EvidenceRecord}
     */
    protected EvidenceRecord getEvidenceRecord(DSSDocument evidenceRecordDocument, ManifestFile manifestFile, ASiCContent asicContent) {
        try {
            EvidenceRecordAnalyzer evidenceRecordAnalyzer = EvidenceRecordAnalyzerFactory.fromDocument(evidenceRecordDocument);
            evidenceRecordAnalyzer.setManifestFile(manifestFile);
            evidenceRecordAnalyzer.setDetachedContents(asicContent.getAllDocuments());
            evidenceRecordAnalyzer.setEvidenceRecordOrigin(EvidenceRecordOrigin.CONTAINER);
            return evidenceRecordAnalyzer.getEvidenceRecord();
        } catch (Exception e) {
            throw new IllegalInputException(String.format(
                    "Unable to build evidence record document. Reason : %s", e.getMessage()));
        }
    }

    /**
     * This method attempts to parse a {@code evidenceRecordManifest} document as an ASiCEvidenceRecordManifest file
     *
     * @param evidenceRecordManifest {@link DSSDocument}
     * @param asicContent {@link ASiCContent}
     * @return {@link ManifestFile}
     */
    protected ManifestFile parseManifestFile(DSSDocument evidenceRecordManifest, ASiCContent asicContent) {
        if (evidenceRecordManifest == null) {
            return null;
        }

        if (evidenceRecordManifest.getName() != null) {
            assertASiCEvidenceRecordManifestValid(evidenceRecordManifest.getName(), asicContent);
        } else {
            evidenceRecordManifest.setName(asicFilenameFactory.getEvidenceRecordManifestFilename(asicContent));
        }

        ManifestFile manifestFile = ASiCManifestParser.getManifestFile(evidenceRecordManifest);
        if (manifestFile == null) {
            throw new IllegalInputException("Unable to parse the provided ASiCEvidenceRecordManifest document! More detail in logs.");
        }
        manifestFile.setManifestType(ASiCManifestTypeEnum.EVIDENCE_RECORD);
        return manifestFile;
    }

    /**
     * This method verifies whether the ASiCEvidenceRecordManifest filename is valid
     *
     * @param manifestFilename {@link String}
     * @param asicContent {@link ASiCContent}
     */
    protected void assertASiCEvidenceRecordManifestValid(String manifestFilename, ASiCContent asicContent) {
        List<String> asicDocumentNames = DSSUtils.getDocumentNames(asicContent.getAllDocuments());
        if (asicDocumentNames.contains(manifestFilename)) {
            throw new IllegalInputException(String.format("The manifest filename '%s' is already present " +
                    "within the ASiC container!", manifestFilename));
        }
        if (!ASiCUtils.isEvidenceRecordManifest(manifestFilename)) {
            throw new IllegalArgumentException(String.format("The manifest filename '%s' is not compliant " +
                    "to the ASiCEvidenceRecordManifest filename convention!", manifestFilename));
        }
    }

    /**
     * This method verifies the validity of the ASiCEvidenceRecordManifest file
     *
     * @param manifestFile {@link ManifestFile} to verify
     * @param asicContent {@link ASiCContent}
     */
    protected void assertManifestFileValid(ManifestFile manifestFile, ASiCContent asicContent) {
        if (manifestFile == null) {
            return;
        }

        final ASiCManifestValidator manifestValidator = new ASiCManifestValidator(manifestFile, asicContent.getAllDocuments());
        manifestValidator.validateEntries();

        for (ManifestEntry manifestEntry : manifestFile.getEntries()) {
            if (!manifestEntry.isFound() || !manifestEntry.isIntact()) {
                throw new IllegalInputException(String.format("The manifest entry '%s' was not found or digest does not intact! " +
                        "Please provide a valid ASiCEvidenceRecordManifest document.", manifestEntry.getUri()));
            }
        }

        List<String> manifestCoveredFilenames = manifestFile.getEntries().stream()
                .map(ManifestEntry::getDocumentName).collect(Collectors.toList());
        assertSignedDataCovered(asicContent, manifestCoveredFilenames);
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

    /**
     * Gets the filename for the evidence record to be incorporated
     *
     * @param evidenceRecord {@link EvidenceRecord}
     * @param manifestFile {@link ManifestFile}
     * @param asicContent {@link ASiCContent}
     * @return {@link String}
     */
    protected String getEvidenceRecordFilename(EvidenceRecord evidenceRecord, ManifestFile manifestFile, ASiCContent asicContent) {
        if (manifestFile != null) {
            return manifestFile.getSignatureFilename();
        }
        return asicFilenameFactory.getEvidenceRecordFilename(asicContent, evidenceRecord.getEvidenceRecordType());
    }

    /**
     * Builds an ASiCEvidenceRecordManifest for the evidence record based on a list of {@code coveredDocuments} when required
     *
     * @param asicContent {@link ASiCContent}
     * @param coveredDocuments a list of {@link DSSDocument}s
     * @param digestAlgorithm {@link DigestAlgorithm}
     * @param evidenceRecordFilename {@link String}
     * @return {@link DSSDocument}
     */
    protected DSSDocument buildEvidenceRecordManifest(ASiCContent asicContent, List<DSSDocument> coveredDocuments,
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

    /**
     * This method verifies whether the provided {@code ASiCContent} is valid and
     * can be successfully protected by a new evidence record
     *
     * @param asicContent {@link ASiCContent} to verify
     * @param parameters {@link ASiCParameters}
     */
    protected void assertASiCContentValid(ASiCContent asicContent, ASiCParameters parameters) {
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
            if (Utils.isCollectionNotEmpty(asicContent.getSignatureDocuments()) ||
                    Utils.isCollectionNotEmpty(asicContent.getTimestampDocuments()) ||
                    Utils.isCollectionNotEmpty(asicContent.getEvidenceRecordDocuments())) {
                throw new IllegalInputException(
                        "Only one of the signature, timestamp or evidence record document types is allowed " +
                                "within an ASiC-S container type!");
            }

        } else {
            throw new UnsupportedOperationException(
                    String.format("Original container type '%s' vs parameter : '%s'", currentContainerType,
                            parameters.getContainerType()));
        }
    }

    /**
     * This method verifies whether the original or signed documents are successfully covered by the evidence record
     *
     * @param asicContent {@link ASiCContent}
     * @param coveredDocumentFilenames a list of document filename {@link String}s covered by the evidence record
     */
    protected void assertSignedDataCovered(ASiCContent asicContent, List<String> coveredDocumentFilenames) {
        final List<String> signedDocumentNames = DSSUtils.getDocumentNames(asicContent.getSignedDocuments());
        for (String signedDocumentFilename : signedDocumentNames) {
            if (!coveredDocumentFilenames.contains(signedDocumentFilename)) {
                throw new IllegalInputException(String.format("The original document with name '%s' is not covered " +
                        "by the evidence record!", signedDocumentFilename));
            }
        }

        for (String documentName : coveredDocumentFilenames) {
            DSSDocument linkedManifest = ASiCManifestParser.getLinkedManifest(asicContent.getAllManifestDocuments(), documentName);
            assertManifestSignedDataCoveredRecursively(linkedManifest, coveredDocumentFilenames, asicContent);
        }
    }

    private void assertManifestSignedDataCoveredRecursively(DSSDocument manifestDocument, List<String> coveredDocumentNames,
                                                            ASiCContent asicContent) {
        if (manifestDocument != null) {
            if (!coveredDocumentNames.contains(manifestDocument.getName())) {
                throw new IllegalInputException(String.format("Digest of a signed ASiC Manifest with name '%s' " +
                        "has not been found in the evidence record's covered objects!", manifestDocument.getName()));
            }
            ManifestFile manifestFile = ASiCManifestParser.getManifestFile(manifestDocument);
            if (manifestFile != null) {
                for (ManifestEntry entry : manifestFile.getEntries()) {
                    if (!coveredDocumentNames.contains(entry.getUri())) {
                        throw new IllegalInputException(String.format("Digest for a document referenced from " +
                                        "a covered ASiC Manifest with name '%s' has not been found in the evidence record's covered objects!",
                                entry.getUri()));
                    }
                    DSSDocument linkedManifest = ASiCManifestParser.getLinkedManifest(asicContent.getAllManifestDocuments(), entry.getUri());
                    assertManifestSignedDataCoveredRecursively(linkedManifest, coveredDocumentNames, asicContent);
                }
            }
        }
    }

    /**
     * This method verifies whether the provided {@code EvidenceRecord} and covers the original data files
     *
     * @param evidenceRecord {@link EvidenceRecord}
     */
    protected void assertEvidenceRecordValid(EvidenceRecord evidenceRecord, ManifestFile manifestFile) {
        if (manifestFile != null) {
            for (ManifestEntry manifestEntry : manifestFile.getEntries()) {
                if (manifestEntry.getDigest() != null && evidenceRecord.getOriginalDigestAlgorithm() != manifestEntry.getDigest().getAlgorithm()) {
                    throw new IllegalInputException(String.format("Digest algorithm '%s' found in the ASiCEvidenceRecordManifest document " +
                            "does not correspond to the Digest Algorithm '%s' used for the first data object group of evidence record generation!",
                            manifestEntry.getDigest().getAlgorithm(), evidenceRecord.getOriginalDigestAlgorithm()));
                }
            }
        }

        final String errorMessage = "The digest covered by the evidence record do not correspond to " +
                "the digest computed on the provided content!";
        boolean signedDataFound = false;
        for (ReferenceValidation referenceValidation : evidenceRecord.getReferenceValidation()) {
            if (DigestMatcherType.EVIDENCE_RECORD_ORPHAN_REFERENCE != referenceValidation.getType()) {
                if (!referenceValidation.isIntact()) {
                    if (referenceValidation.getDocumentName() != null) {
                        throw new IllegalInputException(String.format("The digest of document '%s' has not been found " +
                                "within the manifest file or/and evidence record!", referenceValidation.getDocumentName()));
                    } else {
                        throw new IllegalInputException(errorMessage);
                    }
                }
                signedDataFound = true;
            }
        }
        if (!signedDataFound) {
            throw new IllegalInputException(errorMessage);
        }
        validateTimestamps(evidenceRecord);
    }

    /**
     * This method verifies validity of the evidence record filename to the ASiC container convention
     *
     * @param evidenceRecordFilename {@link String} evidence record filename
     * @param evidenceRecordType {@link EvidenceRecordTypeEnum}
     * @param asicContent {@link ASiCContent}
     */
    protected void assertEvidenceRecordFilenameValid(String evidenceRecordFilename, EvidenceRecordTypeEnum evidenceRecordType,
                                                     ASiCContent asicContent) {
        List<String> asicDocumentNames = DSSUtils.getDocumentNames(asicContent.getAllDocuments());
        if (asicDocumentNames.contains(evidenceRecordFilename)) {
            throw new IllegalInputException(String.format("The evidence record filename '%s' is already present " +
                    "within the ASiC container!", evidenceRecordFilename));
        }
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
