/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.asic.xades.signature;

import eu.europa.esig.dss.asic.common.ASiCContent;
import eu.europa.esig.dss.asic.common.ASiCUtils;
import eu.europa.esig.dss.utils.Utils;

/**
 * This class provides a simple way to define custom names for file entries created within an ASiC with XAdES container,
 * by using set and get methods.
 *
 * This factory adds "META-INF/" prefix to the filename, when required.
 *
 * When a target filename for a particular document type is not specified,
 * then the default processing will take precedence.
 *
 * NOTE: This factory shall be modified when consequently signing/extending a single container.
 *
 * WARN: The class does not verify the conformance of the defined filenames to the EN 319 162-1 standard.
 *
 */
public class SimpleASiCWithXAdESFilenameFactory extends DefaultASiCWithXAdESFilenameFactory {

    private static final long serialVersionUID = 8922794783914081984L;

    /** Defines a name of a creating signature file (e.g. "signatures.xml") */
    private String signatureFilename;

    /** Defines a name of a creating manifest file (e.g. "manifest.xml") */
    private String manifestFilename;

    /** Defines a name of a creating ZIP archive, containing multiple signer documents (in case of ASiC-S container) */
    private String dataPackageFilename;

    /** Defines a new name for the last evidence record manifest file to be created (e.g. "META-INF/ASiCEvidenceRecordManifest001.xml") */
    private String evidenceRecordManifestFilename;

    /**
     * Default constructor instantiating factory with null values
     */
    public SimpleASiCWithXAdESFilenameFactory() {
        // empty
    }

    @Override
    public String getSignatureFilename(ASiCContent asicContent) {
        if (Utils.isStringNotEmpty(signatureFilename)) {
            return getValidSignatureFilename(signatureFilename, asicContent);
        }
        return super.getSignatureFilename(asicContent);
    }

    /**
     * Sets a filename for a new signature document (when applicable).
     *
     * NOTE: The name of the signature file shall be:
     * - ASiC-S with XAdES : "META-INF/signatures.xml";
     * - ASiC-E with XAdES : "META-INF/signatures*.xml";
     * - OpenDocument : "META-INF/documentsignatures.xml".
     * "META-INF/" is optional.
     *
     * @param signatureFilename {@link String}
     */
    public void setSignatureFilename(String signatureFilename) {
        this.signatureFilename = signatureFilename;
    }

    @Override
    public String getManifestFilename(ASiCContent asicContent) {
        if (Utils.isStringNotEmpty(manifestFilename)) {
            return getValidManifestFilename(manifestFilename, asicContent);
        }
        return super.getManifestFilename(asicContent);
    }

    /**
     * Sets a filename for a new manifest document (when applicable).
     *
     * NOTE: The name of the manifest file shall be:
     * - ASiC-E with XAdES : "META-INF/manifest.xml".
     * "META-INF/" is optional.
     *
     * @param manifestFilename {@link String}
     */
    public void setManifestFilename(String manifestFilename) {
        this.manifestFilename = manifestFilename;
    }

    @Override
    public String getDataPackageFilename(ASiCContent asicContent) {
        if (Utils.isStringNotEmpty(dataPackageFilename)) {
            return getValidDataPackageFilename(dataPackageFilename, asicContent);
        }
        return super.getDataPackageFilename(asicContent);
    }

    /**
     * Sets a filename for a new ZIP data package (when applicable).
     *
     * NOTE: The name of the data package file shall be:
     * - ASiC-S with XAdES : "*.zip".
     *
     * @param dataPackageFilename {@link String}
     */
    public void setDataPackageFilename(String dataPackageFilename) {
        this.dataPackageFilename = dataPackageFilename;
    }

    @Override
    public String getEvidenceRecordManifestFilename(ASiCContent asicContent) {
        if (Utils.isStringNotEmpty(evidenceRecordManifestFilename)) {
            return getValidEvidenceRecordManifestFilename(evidenceRecordManifestFilename, asicContent);
        }
        return super.getEvidenceRecordManifestFilename(asicContent);
    }

    /**
     * Sets a new filename for the ASiC evidence record manifest document (when applicable)
     *
     * @param evidenceRecordManifestFilename {@link String}
     */
    public void setEvidenceRecordManifestFilename(String evidenceRecordManifestFilename) {
        this.evidenceRecordManifestFilename = evidenceRecordManifestFilename;
    }

    /**
     * This method returns a valid signature filename
     *
     * @param signatureFilename {@link String} defined signature filename
     * @param asicContent {@link ASiCContent}
     * @return {@link String} signature filename
     */
    protected String getValidSignatureFilename(String signatureFilename, ASiCContent asicContent) {
        signatureFilename = getWithMetaInfFolder(signatureFilename);
        assertFilenameValid(signatureFilename, asicContent.getSignatureDocuments());
        if (ASiCUtils.isASiCSContainer(asicContent) && !ASiCUtils.SIGNATURES_XML.equals(signatureFilename)) {
            throw new IllegalArgumentException(String.format("A signature file within ASiC-S with XAdES container " +
                    "shall have name '%s'!", ASiCUtils.SIGNATURES_XML));

        } else if (ASiCUtils.isOpenDocument(asicContent.getMimeTypeDocument()) &&
                !ASiCUtils.OPEN_DOCUMENT_SIGNATURES.equals(signatureFilename)) {
            throw new IllegalArgumentException(String.format("A signature file within OpenDocument container " +
                    "shall have name '%s'!", ASiCUtils.OPEN_DOCUMENT_SIGNATURES));

        } else if (!signatureFilename.startsWith(ASiCUtils.META_INF_FOLDER + ASiCUtils.SIGNATURES_FILENAME) ||
                !signatureFilename.endsWith(ASiCUtils.XML_EXTENSION)) { // ASiC-E
            throw new IllegalArgumentException(String.format("A signature file within ASiC-E with XAdES container " +
                    "shall match the template '%s'!", ASiCUtils.META_INF_FOLDER + ASiCUtils.SIGNATURES_FILENAME + "*"
                    + ASiCUtils.XML_EXTENSION));
        }
        return signatureFilename;
    }

    /**
     * This method returns a valid manifest filename
     *
     * @param manifestFilename {@link String} defined manifest filename
     * @param asicContent {@link ASiCContent}
     * @return {@link String} manifest filename
     */
    protected String getValidManifestFilename(String manifestFilename, ASiCContent asicContent) {
        manifestFilename = getWithMetaInfFolder(manifestFilename);
        assertFilenameValid(manifestFilename, asicContent.getManifestDocuments());
        if (!ASiCUtils.ASICE_METAINF_MANIFEST.equals(manifestFilename)) {
            throw new IllegalArgumentException(String.format("A manifest file within ASiC with XAdES container " +
                    "shall have name '%s'!", ASiCUtils.ASICE_METAINF_MANIFEST));
        }
        return manifestFilename;
    }

}
