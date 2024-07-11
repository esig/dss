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
package eu.europa.esig.dss.asic.common.evidencerecord;

import eu.europa.esig.dss.asic.common.ASiCContent;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.utils.Utils;

import java.util.ArrayList;
import java.util.Collection;
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
     * Returns a list of filtered {@code DSSDocument}s according to the configuration
     *
     * @param asicContent {@link ASiCContent} representing the ASiC container to get documents from
     * @return a list of {@link DSSDocument}s
     */
    public List<DSSDocument> filter(ASiCContent asicContent) {
        final List<DSSDocument> result = new ArrayList<>();
        if (mimetypeDocument && asicContent.getMimeTypeDocument() != null) {
            DSSDocument mimeTypeDocument = asicContent.getMimeTypeDocument();
            if (Utils.isCollectionEmpty(excludedFilenames) || !excludedFilenames.contains(mimeTypeDocument.getName())) {
                result.add(mimeTypeDocument);
            }
        }
        if (signedDocuments) {
            result.addAll(filterDocuments(asicContent.getSignedDocuments()));
        }
        if (signatureDocuments) {
            result.addAll(filterDocuments(asicContent.getSignatureDocuments()));
        }
        if (timestampDocuments) {
            result.addAll(filterDocuments(asicContent.getTimestampDocuments()));
        }
        if (evidenceRecordDocuments) {
            result.addAll(filterDocuments(asicContent.getEvidenceRecordDocuments()));
        }
        if (manifestDocuments) {
            result.addAll(filterDocuments(asicContent.getManifestDocuments()));
        }
        if (archiveManifestDocuments) {
            result.addAll(filterDocuments(asicContent.getArchiveManifestDocuments()));
        }
        if (evidenceRecordManifestDocuments) {
            result.addAll(filterDocuments(asicContent.getEvidenceRecordManifestDocuments()));
        }
        if (unsupportedDocuments) {
            result.addAll(filterDocuments(asicContent.getUnsupportedDocuments()));
        }
        return result;
    }

    private Collection<DSSDocument> filterDocuments(Collection<DSSDocument> documents) {
        if (Utils.isCollectionEmpty(excludedFilenames)) {
            return documents;
        }
        return documents.stream().filter(d -> !excludedFilenames.contains(d.getName())).collect(Collectors.toList());
    }

}
