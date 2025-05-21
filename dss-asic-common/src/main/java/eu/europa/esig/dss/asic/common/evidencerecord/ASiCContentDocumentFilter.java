package eu.europa.esig.dss.asic.common.evidencerecord;

import eu.europa.esig.dss.asic.common.ASiCContent;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.utils.Utils;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

/**
 * This class provides a configuration to filter the content of an ASiC container.
 * Example: the class can be used to define type of documents to be protected by an evidence record
 * (see {@code eu.europa.esig.dss.asic.common.evidencerecord.ASiCEvidenceRecordDigestBuilder})
 * See {@code eu.europa.esig.dss.asic.common.evidencerecord.ASiCContentDocumentFilterFactory} class for creating
 * of pre-configured instances for basic usages
 *
 */
public class ASiCContentDocumentFilter {

    /**
     * Defines whether the mimetype document within a root folder of the container shall be returned
     */
    private boolean mimetypeDocument;

    /**
     * Defines whether the original signed documents from the container shall be returned
     */
    private boolean signedDocuments;

    /**
     * Defines whether the signature documents within a META-INF/ folder of the container shall be returned
     */
    private boolean signatureDocuments;

    /**
     * Defines whether the time-stamp documents within a META-INF/ folder of the container shall be returned
     */
    private boolean timestampDocuments;

    /**
     * Defines whether the evidence record documents within a META-INF/ folder of the container shall be returned
     */
    private boolean evidenceRecordDocuments;

    /**
     * Defines whether the manifest documents within a META-INF/ folder of the container shall be returned
     */
    private boolean manifestDocuments;

    /**
     * Defines whether the archive manifest documents within a META-INF/ folder of the container shall be returned
     */
    private boolean archiveManifestDocuments;

    /**
     * Defines whether the evidence record manifest documents within a META-INF/ folder of the container shall be returned
     */
    private boolean evidenceRecordManifestDocuments;

    /**
     * Defines whether other documents not directly supported by EN 319 162-1 specification shall be returned
     */
    private boolean unsupportedDocuments;

    /**
     * Contains a collection of filenames (including the directory path) to be excluded from the returned result
     */
    private Collection<String> excludedFilenames;

    /**
     * Contains a collection of filenames (including the directory path) to be including despite the other settings
     */
    private Collection<String> includedFilenames;

    /**
     * Default constructor instantiating an ASiCContentDocumentFilter object with an empty configuration
     */
    public ASiCContentDocumentFilter() {
        // empty
    }

    /**
     * Sets whether the mimetype document present at the root level shall be returned
     *
     * @param mimetypeDocument whether the mimetype document present at the root level shall be returned
     */
    public void setMimetypeDocument(boolean mimetypeDocument) {
        this.mimetypeDocument = mimetypeDocument;
    }

    /**
     * Sets whether the original signed documents shall be returned
     *
     * @param signedDocuments whether the original signed documents present at the root level shall be returned
     */
    public void setSignedDocuments(boolean signedDocuments) {
        this.signedDocuments = signedDocuments;
    }

    /**
     * Sets whether the signature documents present within a META-INF/ folder shall be returned
     *
     * @param signatureDocuments whether the signature documents present within a META-INF/ folder shall be returned
     */
    public void setSignatureDocuments(boolean signatureDocuments) {
        this.signatureDocuments = signatureDocuments;
    }

    /**
     * Sets whether the time-stamp documents present within a META-INF/ folder shall be returned
     *
     * @param timestampDocuments whether the time-stamp documents present within a META-INF/ folder shall be returned
     */
    public void setTimestampDocuments(boolean timestampDocuments) {
        this.timestampDocuments = timestampDocuments;
    }

    /**
     * Sets whether the evidence record documents present within a META-INF/ folder shall be returned
     *
     * @param evidenceRecordDocuments whether the evidence record documents present within a META-INF/ folder shall be returned
     */
    public void setEvidenceRecordDocuments(boolean evidenceRecordDocuments) {
        this.evidenceRecordDocuments = evidenceRecordDocuments;
    }

    /**
     * Sets whether the ASiC manifest documents present within a META-INF/ folder shall be returned
     *
     * @param manifestDocuments whether the ASiC manifest documents present within a META-INF/ folder shall be returned
     */
    public void setManifestDocuments(boolean manifestDocuments) {
        this.manifestDocuments = manifestDocuments;
    }

    /**
     * Sets whether the archive ASiC manifest documents present within a META-INF/ folder shall be returned
     *
     * @param archiveManifestDocuments whether the archive ASiC manifest documents present within a META-INF/ folder shall be returned
     */
    public void setArchiveManifestDocuments(boolean archiveManifestDocuments) {
        this.archiveManifestDocuments = archiveManifestDocuments;
    }

    /**
     * Sets whether the evidence record manifest documents present within a META-INF/ folder shall be returned
     *
     * @param evidenceRecordManifestDocuments whether the evidence record manifest documents present within a META-INF/ folder shall be returned
     */
    public void setEvidenceRecordManifestDocuments(boolean evidenceRecordManifestDocuments) {
        this.evidenceRecordManifestDocuments = evidenceRecordManifestDocuments;
    }

    /**
     * Sets whether other documents not directly supported by EN 319 162-1 specification shall be returned
     *
     * @param unsupportedDocuments whether other documents not directly supported by EN 319 162-1 specification shall be returned
     */
    public void setUnsupportedDocuments(boolean unsupportedDocuments) {
        this.unsupportedDocuments = unsupportedDocuments;
    }

    /**
     * Sets a collection of document filenames to be excluded from the final return result
     *
     * @param excludedFilenames a collection of {@link String} document filenames to be excluded
     */
    public void setExcludedFilenames(Collection<String> excludedFilenames) {
        this.excludedFilenames = excludedFilenames;
    }

    /**
     * Sets a collection of document filenames to be included in the final return result despite other settings.
     * NOTE: take precedence over all other constraints.
     *
     * @param includedFilenames a collection of {@link String} document filenames to be included
     */
    public void setIncludedFilenames(Collection<String> includedFilenames) {
        this.includedFilenames = includedFilenames;
    }

    /**
     * Returns a list of filtered {@code DSSDocument}s according to the configuration
     *
     * @param asicContent {@link ASiCContent} representing the ASiC container to get documents from
     * @return a list of {@link DSSDocument}s
     */
    public List<DSSDocument> filter(ASiCContent asicContent) {
        final List<DSSDocument> result = new ArrayList<>();
        if (asicContent.getMimeTypeDocument() != null) {
            result.addAll(filterDocuments(Collections.singletonList(asicContent.getMimeTypeDocument()), mimetypeDocument));
        }
        result.addAll(filterDocuments(asicContent.getSignedDocuments(), signedDocuments));
        result.addAll(filterDocuments(asicContent.getSignatureDocuments(), signatureDocuments));
        result.addAll(filterDocuments(asicContent.getTimestampDocuments(), timestampDocuments));
        result.addAll(filterDocuments(asicContent.getEvidenceRecordDocuments(), evidenceRecordDocuments));
        result.addAll(filterDocuments(asicContent.getManifestDocuments(), manifestDocuments));
        result.addAll(filterDocuments(asicContent.getArchiveManifestDocuments(), archiveManifestDocuments));
        result.addAll(filterDocuments(asicContent.getEvidenceRecordManifestDocuments(), evidenceRecordManifestDocuments));
        result.addAll(filterDocuments(asicContent.getUnsupportedDocuments(), unsupportedDocuments));
        return result;
    }

    private Collection<DSSDocument> filterDocuments(Collection<DSSDocument> documents, boolean formatSupported) {
        final List<DSSDocument> result = new ArrayList<>();
        if (Utils.isCollectionNotEmpty(includedFilenames)) {
            documents.stream().filter(d -> includedFilenames.contains(d.getName())).forEach(result::add);
        }
        if (!formatSupported) {
            return result;
        }
        if (Utils.isCollectionEmpty(excludedFilenames)) {
            return documents;
        }
        return documents.stream().filter(d -> !result.contains(d) && !excludedFilenames.contains(d.getName())).collect(Collectors.toList());
    }

}
