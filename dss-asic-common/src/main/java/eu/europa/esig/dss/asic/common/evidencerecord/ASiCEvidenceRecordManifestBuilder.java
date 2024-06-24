package eu.europa.esig.dss.asic.common.evidencerecord;

import eu.europa.esig.dss.asic.common.ASiCContent;
import eu.europa.esig.dss.asic.common.ASiCEvidenceRecordFilenameFactory;
import eu.europa.esig.dss.asic.common.AbstractASiCManifestBuilder;
import eu.europa.esig.dss.asic.common.extract.ASiCContainerExtractor;
import eu.europa.esig.dss.asic.common.extract.DefaultASiCContainerExtractor;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.MimeType;
import eu.europa.esig.dss.spi.exception.IllegalInputException;
import eu.europa.esig.dss.model.DSSDocument;

/**
 * Builds an ASiCManifest for an Evidence Record
 */
public class ASiCEvidenceRecordManifestBuilder extends AbstractASiCManifestBuilder {

    /**
     * Defines rules for filename creation for new manifest files.
     */
    private ASiCEvidenceRecordFilenameFactory evidenceRecordFilenameFactory;

    /**
     * Constructor to build a manifest from a {@code eu.europa.esig.dss.model.DSSDocument} representing the ASiC container
     *
     * @param asicContainer {@link DSSDocument}
     * @param digestAlgorithm {@link DigestAlgorithm} to use for digest calculation
     * @param evidenceRecordFilename {@link String} the filename of the evidence record to be associated with the manifest
     */
    public ASiCEvidenceRecordManifestBuilder(final DSSDocument asicContainer, final DigestAlgorithm digestAlgorithm,
                                             final String evidenceRecordFilename) {
        this(toASiCContent(asicContainer), digestAlgorithm, evidenceRecordFilename);
    }

    private static ASiCContent toASiCContent(final DSSDocument asicContainer) {
        try {
            ASiCContainerExtractor asicContainerExtractor = DefaultASiCContainerExtractor.fromDocument(asicContainer);
            return asicContainerExtractor.extract();
        } catch (Exception e) {
            throw new IllegalInputException(String.format("Unsupported ASiC or document type! Returned error : %s", e.getMessage()), e);
        }
    }

    /**
     * Constructor to build a manifest from a {@code ASiCContent} representing the ASiC container
     *
     * @param asicContent {@link ASiCContent}
     * @param digestAlgorithm {@link DigestAlgorithm} to use for digest calculation
     * @param evidenceRecordFilename {@link String} the filename of the evidence record to be associated with the manifest
     */
    public ASiCEvidenceRecordManifestBuilder(final ASiCContent asicContent, final DigestAlgorithm digestAlgorithm,
            final String evidenceRecordFilename) {
        super(asicContent, evidenceRecordFilename, digestAlgorithm);
    }

    @Override
    protected MimeType getSigReferenceMimeType() {
        // not required for an evidence record
        return null;
    }

    @Override
    protected ASiCContentDocumentFilter initDefaultAsicContentDocumentFilter() {
        return ASiCContentDocumentFilterFactory.archiveDocumentsFilter();
    }

    @Override
    public ASiCEvidenceRecordManifestBuilder setAsicContentDocumentFilter(ASiCContentDocumentFilter asicContentDocumentFilter) {
        return (ASiCEvidenceRecordManifestBuilder) super.setAsicContentDocumentFilter(asicContentDocumentFilter);
    }

    /**
     * Sets an ASiC evidence record filename factory, used to provide a valid filename
     * for the ASiC Evidence Record Manifest document to be created.
     * Note: when not set, final {@code DSSDocument} will have name set to NULL.
     *
     * @param evidenceRecordFilenameFactory {@link ASiCEvidenceRecordFilenameFactory}
     * @return this {@link ASiCEvidenceRecordManifestBuilder}
     */
    public ASiCEvidenceRecordManifestBuilder setEvidenceRecordFilenameFactory(ASiCEvidenceRecordFilenameFactory evidenceRecordFilenameFactory) {
        this.evidenceRecordFilenameFactory = evidenceRecordFilenameFactory;
        return this;
    }

    @Override
    protected String getManifestFilename() {
        if (evidenceRecordFilenameFactory != null) {
            return evidenceRecordFilenameFactory.getEvidenceRecordManifestFilename(asicContent);
        }
        return null;
    }

}
