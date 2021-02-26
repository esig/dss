package eu.europa.esig.dss.asic.cades.signature;

import eu.europa.esig.dss.asic.cades.validation.ASiCWithCAdESManifestParser;
import eu.europa.esig.dss.asic.cades.validation.ASiCWithCAdESTimestampValidator;
import eu.europa.esig.dss.cades.validation.CAdESSignature;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.ManifestEntry;
import eu.europa.esig.dss.validation.ManifestFile;
import eu.europa.esig.dss.validation.ValidationContext;
import eu.europa.esig.dss.validation.ValidationDataForInclusion;
import eu.europa.esig.dss.validation.ValidationDataForInclusionBuilder;
import eu.europa.esig.dss.validation.timestamp.TimestampToken;
import org.bouncycastle.cms.CMSSignedData;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * Builds {@code ValidationDataForInclusion} to be included into the last archival timestamp
 * for ASiC with CAdES extension
 *
 */
public class ASiCWithCAdESValidationDataForInclusionBuilder {

    private static final Logger LOG = LoggerFactory.getLogger(ASiCWithCAdESValidationDataForInclusionBuilder.class);

    /** The {@code CertificateVerifier} to validate the signature/timestamp */
    private final CertificateVerifier certificateVerifier;

    /** The last ASiCArchiveManifest.xml file */
    private final ManifestFile archiveManifestFile;

    /** Represents a list of signatures to get validation data for */
    private List<DSSDocument> signatures;

    /** Represents a list of timestamps to get validation data for */
    private List<DSSDocument> timestamps;

    /** A list of all manifests present within the container */
    private List<DSSDocument> manifests;

    /**
     * Default constructor
     *
     * @param certificateVerifier {@link CertificateVerifier}
     * @param archiveManifestFile {@link ManifestFile} representing the last ASiCArchiveManifest.xml file
     */
    public ASiCWithCAdESValidationDataForInclusionBuilder(final CertificateVerifier certificateVerifier,
                                                          final ManifestFile archiveManifestFile) {
        this.certificateVerifier = certificateVerifier;
        this.archiveManifestFile = archiveManifestFile;
    }

    /**
     * Sets a list of signature documents incorporated within the ASiC container
     *
     * @param signatures a list of {@link DSSDocument}s
     * @return this {@link ASiCWithCAdESValidationDataForInclusionBuilder}
     */
    public ASiCWithCAdESValidationDataForInclusionBuilder setSignatures(List<DSSDocument> signatures) {
        this.signatures = signatures;
        return this;
    }

    /**
     * Sets a list of timestamp documents incorporated within the ASiC container
     *
     * @param timestamps a list of {@link DSSDocument}s
     * @return this {@link ASiCWithCAdESValidationDataForInclusionBuilder}
     */
    public ASiCWithCAdESValidationDataForInclusionBuilder setTimestamps(List<DSSDocument> timestamps) {
        this.timestamps = timestamps;
        return this;
    }

    /**
     * Sets a list of manifest files present within the container
     *
     * @param manifests a list of {@link DSSDocument}s
     * @return this {@link ASiCWithCAdESValidationDataForInclusionBuilder}
     */
    public ASiCWithCAdESValidationDataForInclusionBuilder setManifests(List<DSSDocument> manifests) {
        this.manifests = manifests;
        return this;
    }

    /**
     * Builds {@code ValidationDataForInclusion}
     *
     * @return {@link ValidationDataForInclusion}
     */
    public ValidationDataForInclusion build() {
        ValidationDataForInclusion validationDataForInclusion = new ValidationDataForInclusion();
        List<TimestampToken> timestampTokens = createTimestampTokensFromDocuments();
        /*
         * 2) When adding a new ASiCArchiveManifest file, the time-stamp token applied to
         * the last ASiCArchiveManifest file shall include the full information required for
         * its validation as specified in the item 1 above, and:
         * ...
         * b) the new ASiCArchiveManifest file shall:
         * ...
         * iii) reference all the signed and/or time-stamped file objects requiring long term availability and
         * integrity guarantee, including all the file objects referenced by the ASiCArchiveManifest files
         * already present, the ASiCArchiveManifest files already present, and the time-stamp tokens that
         * apply to them;
         */
        for (ManifestEntry manifestEntry : archiveManifestFile.getEntries()) {
            String fileName = manifestEntry.getFileName();
            if (Utils.isStringNotBlank(fileName)) {
                DSSDocument documentToValidate = DSSUtils.getDocumentWithName(signatures, fileName);
                if (documentToValidate == null) {
                    documentToValidate = DSSUtils.getDocumentWithName(timestamps, fileName);
                }
                if (documentToValidate != null) {
                    CAdESSignature signature = createSignature(documentToValidate);

                    List<TimestampToken> archiveTimestampTokens = getTimestampsCoveringTheSignature(timestampTokens, fileName);
                    populateExternalTimestamps(signature, archiveTimestampTokens);

                    ValidationDataForInclusion validationDataForDocument = getValidationDataForSignature(signature);
                    populateValidationDataForInclusion(validationDataForInclusion, validationDataForDocument);
                }
            }
        }
        return validationDataForInclusion;
    }

    private List<TimestampToken> createTimestampTokensFromDocuments() {
        if (Utils.isCollectionNotEmpty(timestamps)) {
            List<TimestampToken> timestampTokens = new ArrayList<>();
            for (DSSDocument document : timestamps) {
                // only timestamps covering a signature/timestamp are considered
                ASiCWithCAdESTimestampValidator validator = new ASiCWithCAdESTimestampValidator(
                        document, TimestampType.ARCHIVE_TIMESTAMP);
                validator.setCertificateVerifier(certificateVerifier);

                ManifestFile manifestFile = getManifestFileForSignatureWithName(document.getName());
                if (manifestFile != null) {
                    validator.setManifestFile(manifestFile);
                    validator.setDetachedContents(Arrays.asList(manifestFile.getDocument()));

                    timestampTokens.add(validator.getTimestamp());

                } else {
                    LOG.warn("Manifest is not found for a timestamp with name '{}'!", document.getName());
                }

            }
            return timestampTokens;
        }
        return Collections.emptyList();
    }

    private List<TimestampToken> getTimestampsCoveringTheSignature(List<TimestampToken> timestamps, String fileName) {
        List<TimestampToken> result = new ArrayList<>();
        for (TimestampToken timestampToken : timestamps) {
            ManifestFile manifestFile = timestampToken.getManifestFile();
            if (manifestFile != null && coversFileWithName(manifestFile, fileName)) {
                result.add(timestampToken);
            }
        }
        return result;
    }

    private void populateExternalTimestamps(CAdESSignature signature, List<TimestampToken> timestampTokens) {
        for (TimestampToken timestampToken : timestampTokens) {
            signature.addExternalTimestamp(timestampToken);
        }
    }

    private boolean coversFileWithName(ManifestFile manifestFile, String fileName) {
        for (ManifestEntry entry : manifestFile.getEntries()) {
            if (fileName.equals(entry.getFileName())) {
                return true;
            }
        }
        return false;
    }

    private CAdESSignature createSignature(DSSDocument document) {
        CMSSignedData cmsSignedData = DSSUtils.toCMSSignedData(document);
        CAdESSignature cadesSignature = new CAdESSignature(cmsSignedData, cmsSignedData.getSignerInfos().iterator().next());
        ManifestFile signedManifest = getManifestFileForSignatureWithName(document.getName());
        if (signedManifest != null) {
            cadesSignature.setDetachedContents(Arrays.asList(signedManifest.getDocument()));
        }
        return cadesSignature;
    }

    private ValidationDataForInclusion getValidationDataForSignature(CAdESSignature signature) {
        try {
            ValidationContext validationContext = signature.getSignatureValidationContext(certificateVerifier);
            ValidationDataForInclusionBuilder validationDataForInclusionBuilder =
                    new ValidationDataForInclusionBuilder(validationContext, signature.getCompleteCertificateSource())
                            .excludeCertificateTokens(signature.getCompleteCertificateSource().getAllCertificateTokens())
                            .excludeCRLs(signature.getCompleteCRLSource().getAllRevocationBinaries())
                            .excludeOCSPs(signature.getCompleteOCSPSource().getAllRevocationBinaries());
            return validationDataForInclusionBuilder.build();

        } catch (Exception e) {
            String message = "Cannot extract validation data for a signature with name '{}'. Reason : {}";
            if (LOG.isDebugEnabled()) {
                LOG.warn(message, signature.getSignatureFilename(), e.getMessage(), e);
            } else {
                LOG.warn(message, signature.getSignatureFilename(), e.getMessage());
            }

            // return empty
            return new ValidationDataForInclusion();
        }
    }

    private ManifestFile getManifestFileForSignatureWithName(String fileName) {
        if (fileName.equals(archiveManifestFile.getSignatureFilename())) {
            return archiveManifestFile;
        }
        if (Utils.isCollectionNotEmpty(manifests)) {
            for (DSSDocument manifest : manifests) {
                ManifestFile manifestFile = ASiCWithCAdESManifestParser.getManifestFile(manifest);
                if (fileName.equals(manifestFile.getSignatureFilename())) {
                    return manifestFile;
                }
            }
        }
        return null;
    }

    private void populateValidationDataForInclusion(final ValidationDataForInclusion validationDataForInclusion,
                                                    ValidationDataForInclusion dataToAdd) {
        validationDataForInclusion.getCertificateTokens().addAll(dataToAdd.getCertificateTokens());
        validationDataForInclusion.getCrlTokens().addAll(dataToAdd.getCrlTokens());
        validationDataForInclusion.getOcspTokens().addAll(dataToAdd.getOcspTokens());
    }

}
