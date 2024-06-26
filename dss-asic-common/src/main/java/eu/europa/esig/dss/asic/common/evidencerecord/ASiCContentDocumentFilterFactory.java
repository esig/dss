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

import eu.europa.esig.dss.utils.Utils;

import java.util.Arrays;

/**
 * Helper class to create {@code eu.europa.esig.dss.asic.common.evidencerecord.ASiCContentDocumentFilter}
 *
 */
public class ASiCContentDocumentFilterFactory {

    /**
     * Creates an {@code ASiCContentDocumentFilter} with an empty configuration
     *
     * @return {@link ASiCContentDocumentFilter}
     */
    public static ASiCContentDocumentFilter emptyFilter() {
        return new ASiCContentDocumentFilter();
    }

    /**
     * Creates an {@code ASiCContentDocumentFilter} with a configuration to return only original singed documents
     * Note: This is a default configuration for an ASiCManifest (signed or time-stamped)
     *
     * @param excludedFilenames (optional) an array of {@link String}s to be excluded (e.g. the current ASiCManifest.xml)
     * @return {@link ASiCContentDocumentFilter}
     */
    public static ASiCContentDocumentFilter signedDocumentsOnlyFilter(String... excludedFilenames) {
        final ASiCContentDocumentFilter asicContentDocumentFilter = emptyFilter();
        asicContentDocumentFilter.setSignedDocuments(true);
        if (Utils.isArrayNotEmpty(excludedFilenames)) {
            asicContentDocumentFilter.setExcludedFilenames(Arrays.asList(excludedFilenames));
        }
        return asicContentDocumentFilter;
    }

    /**
     * Creates an {@code ASiCContentDocumentFilter} with a configuration returning original signed documents,
     * signature and time-stamp documents, as well as the corresponding manifest files
     * Note: This is a default configuration for an ASiCArchiveManifest
     *
     * @param excludedFilenames (optional) an array of {@link String}s to be excluded (e.g. the current ASiCArchiveManifest.xml)
     * @return {@link ASiCContentDocumentFilter}
     */
    public static ASiCContentDocumentFilter archiveDocumentsFilter(String... excludedFilenames) {
        final ASiCContentDocumentFilter asicContentDocumentFilter = emptyFilter();
        asicContentDocumentFilter.setSignedDocuments(true);
        asicContentDocumentFilter.setSignatureDocuments(true);
        asicContentDocumentFilter.setTimestampDocuments(true);
        asicContentDocumentFilter.setManifestDocuments(true);
        asicContentDocumentFilter.setArchiveManifestDocuments(true);
        if (Utils.isArrayNotEmpty(excludedFilenames)) {
            asicContentDocumentFilter.setExcludedFilenames(Arrays.asList(excludedFilenames));
        }
        return asicContentDocumentFilter;
    }

    /**
     * Creates an {@code ASiCContentDocumentFilter} returning all recognized type documents available (without mimetype),
     * within an {@code eu.europa.esig.dss.asic.common.ASiCContent}, excluding the documents with filenames defined in
     * {@code excludedFilenames}
     *
     * @param excludedFilenames (optional) an array of {@link String}s to be excluded
     * @return {@link ASiCContentDocumentFilter}
     */
    public static ASiCContentDocumentFilter allSupportedDocumentsFilter(String... excludedFilenames) {
        final ASiCContentDocumentFilter asicContentDocumentFilter = emptyFilter();
        asicContentDocumentFilter.setSignedDocuments(true);
        asicContentDocumentFilter.setSignatureDocuments(true);
        asicContentDocumentFilter.setTimestampDocuments(true);
        asicContentDocumentFilter.setEvidenceRecordDocuments(true);
        asicContentDocumentFilter.setManifestDocuments(true);
        asicContentDocumentFilter.setArchiveManifestDocuments(true);
        asicContentDocumentFilter.setEvidenceRecordManifestDocuments(true);
        if (Utils.isArrayNotEmpty(excludedFilenames)) {
            asicContentDocumentFilter.setExcludedFilenames(Arrays.asList(excludedFilenames));
        }
        return asicContentDocumentFilter;
    }

    /**
     * Creates an {@code ASiCContentDocumentFilter} returning all documents available, including unrecognized documents
     * and mimetype document, within an {@code eu.europa.esig.dss.asic.common.ASiCContent}, excluding the documents
     * with filenames defined in {@code excludedFilenames}
     *
     * @param excludedFilenames (optional) an array of {@link String}s to be excluded
     * @return {@link ASiCContentDocumentFilter}
     */
    public static ASiCContentDocumentFilter allDocumentsFilter(String... excludedFilenames) {
        final ASiCContentDocumentFilter asicContentDocumentFilter = emptyFilter();
        asicContentDocumentFilter.setMimetypeDocument(true);
        asicContentDocumentFilter.setSignedDocuments(true);
        asicContentDocumentFilter.setSignatureDocuments(true);
        asicContentDocumentFilter.setTimestampDocuments(true);
        asicContentDocumentFilter.setEvidenceRecordDocuments(true);
        asicContentDocumentFilter.setManifestDocuments(true);
        asicContentDocumentFilter.setArchiveManifestDocuments(true);
        asicContentDocumentFilter.setEvidenceRecordManifestDocuments(true);
        asicContentDocumentFilter.setUnsupportedDocuments(true);
        if (Utils.isArrayNotEmpty(excludedFilenames)) {
            asicContentDocumentFilter.setExcludedFilenames(Arrays.asList(excludedFilenames));
        }
        return asicContentDocumentFilter;
    }

}
