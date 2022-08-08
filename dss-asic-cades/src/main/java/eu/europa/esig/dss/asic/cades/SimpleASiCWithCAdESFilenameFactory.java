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
package eu.europa.esig.dss.asic.cades;

import eu.europa.esig.dss.asic.cades.validation.ASiCWithCAdESUtils;
import eu.europa.esig.dss.asic.common.ASiCContent;
import eu.europa.esig.dss.asic.common.ASiCUtils;
import eu.europa.esig.dss.utils.Utils;

/**
 * This class provides a simple way to define custom names for file entries created within an ASiC with CAdES container,
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
public class SimpleASiCWithCAdESFilenameFactory extends DefaultASiCWithCAdESFilenameFactory {

    private static final long serialVersionUID = 8401330459709076998L;

    /** Defines a name of a creating signature file (e.g. "signature001.p7s") */
    private String signatureFilename;

    /** Defines a name of a creating timestamp file (e.g. "timestamp001.tst") */
    private String timestampFilename;

    /** Defines a name of a creating manifest file (e.g. "ASiCManifest001.xml") */
    private String manifestFilename;

    /** Defines a new name for the last archive manifest file to be moved (e.g. "ASiCArchiveManifest001.xml") */
    private String archiveManifestFilename;

    /** Defines a name of a creating ZIP archive, containing multiple signer documents (in case of ASiC-S container) */
    private String dataPackageFilename;

    /**
     * Default constructor instantiating factory with null values
     */
    public SimpleASiCWithCAdESFilenameFactory() {
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
     * - ASiC-S with CAdES : "META-INF/signature.p7s";
     * - ASiC-E with CAdES : "META-INF/signature*.p7s".
     * "META-INF/" is optional.
     *
     * @param signatureFilename {@link String}
     */
    public void setSignatureFilename(String signatureFilename) {
        this.signatureFilename = signatureFilename;
    }

    @Override
    public String getTimestampFilename(ASiCContent asicContent) {
        if (Utils.isStringNotEmpty(timestampFilename)) {
            return getValidTimestampFilename(timestampFilename, asicContent);
        }
        return super.getTimestampFilename(asicContent);
    }

    /**
     * Sets a filename for a new timestamp document (when applicable).
     *
     * NOTE: The name of the timestamp file shall be:
     * - ASiC-S with CAdES : "META-INF/timestamp.tst";
     * - ASiC-E with CAdES : "META-INF/timestamp*.tst".
     * "META-INF/" is optional.
     *
     * @param timestampFilename {@link String}
     */
    public void setTimestampFilename(String timestampFilename) {
        this.timestampFilename = timestampFilename;
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
     * NOTE: The name of the timestamp file shall be:
     * - ASiC-E with CAdES : "META-INF/ASiCManifest*.xml".
     * "META-INF/" is optional.
     *
     * @param manifestFilename {@link String}
     */
    public void setManifestFilename(String manifestFilename) {
        this.manifestFilename = manifestFilename;
    }

    @Override
    public String getArchiveManifestFilename(ASiCContent asicContent) {
        if (Utils.isStringNotEmpty(archiveManifestFilename)) {
            return getValidArchiveManifestFilename(archiveManifestFilename, asicContent);
        }
        return super.getArchiveManifestFilename(asicContent);
    }

    /**
     * Sets a new filename for the last archive manifest document (when applicable)
     *
     * @param archiveManifestFilename {@link String}
     */
    public void setArchiveManifestFilename(String archiveManifestFilename) {
        this.archiveManifestFilename = archiveManifestFilename;
    }

    @Override
    public String getDataPackageFilename(ASiCContent asicContent) {
        if (Utils.isStringNotEmpty(dataPackageFilename)) {
            return getValidDataPackageFilename(dataPackageFilename, asicContent);
        }
        return super.getDataPackageFilename(asicContent);
    }

    /**
     * Sets a filename for a new ZIP data package (when applicable)
     *
     * @param dataPackageFilename {@link String}
     */
    public void setDataPackageFilename(String dataPackageFilename) {
        this.dataPackageFilename = dataPackageFilename;
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
        if (ASiCUtils.isASiCSContainer(asicContent) && !ASiCUtils.SIGNATURE_P7S.equals(signatureFilename)) {
            throw new IllegalArgumentException(String.format("A signature file within ASiC-S with CAdES container " +
                    "shall have name '%s'!", ASiCUtils.SIGNATURE_P7S));

        } else if (!signatureFilename.startsWith(ASiCUtils.META_INF_FOLDER + ASiCUtils.SIGNATURE_FILENAME) ||
                !signatureFilename.endsWith(ASiCUtils.CADES_SIGNATURE_EXTENSION)) { // ASiC-E
            throw new IllegalArgumentException(String.format("A signature file within ASiC-E with CAdES container " +
                    "shall match the template '%s'!", ASiCUtils.META_INF_FOLDER + ASiCUtils.SIGNATURE_FILENAME + "*"
                    + ASiCUtils.CADES_SIGNATURE_EXTENSION));
        }
        return signatureFilename;
    }
    /**
     * This method returns a valid timestamp filename
     *
     * @param timestampFilename {@link String} defined timestamp filename
     * @param asicContent {@link ASiCContent}
     * @return {@link String} timestamp filename
     */
    protected String getValidTimestampFilename(String timestampFilename, ASiCContent asicContent) {
        timestampFilename = getWithMetaInfFolder(timestampFilename);
        assertFilenameValid(timestampFilename, asicContent.getTimestampDocuments());
        if (ASiCUtils.isASiCSContainer(asicContent) && Utils.isCollectionEmpty(asicContent.getTimestampDocuments()) &&
                !ASiCUtils.TIMESTAMP_TST.equals(timestampFilename)) {
            throw new IllegalArgumentException(String.format("A timestamp file within ASiC-S with CAdES container " +
                    "shall have name '%s'!", ASiCUtils.TIMESTAMP_TST));

        } else if (!timestampFilename.startsWith(ASiCUtils.META_INF_FOLDER + ASiCUtils.TIMESTAMP_FILENAME) ||
                !timestampFilename.endsWith(ASiCUtils.TST_EXTENSION)) { // ASiC-E
            throw new IllegalArgumentException(String.format("A timestamp file within ASiC-E with CAdES container " +
                    "shall match the template '%s'!", ASiCUtils.META_INF_FOLDER + ASiCUtils.TIMESTAMP_FILENAME + "*"
                    + ASiCUtils.TST_EXTENSION));
        }
        return timestampFilename;
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
        if (!manifestFilename.startsWith(ASiCUtils.META_INF_FOLDER + ASiCUtils.ASIC_MANIFEST_FILENAME) ||
                !manifestFilename.endsWith(ASiCUtils.XML_EXTENSION)) {
            throw new IllegalArgumentException(String.format("A manifest file within ASiC with CAdES container " +
                    "shall match the template '%s'!", ASiCUtils.META_INF_FOLDER + ASiCUtils.ASIC_MANIFEST_FILENAME + "*"
                    + ASiCUtils.XML_EXTENSION));
        }
        return manifestFilename;
    }

    /**
     * This method returns a valid archive manifest filename.
     *
     * NOTE: The name of the timestamp file shall be:
     * - ASiC-E with CAdES : "META-INF/ASiCArchiveManifest*.xml".
     * "META-INF/" is optional.
     *
     * @param archiveManifestFilename {@link String} defined archive manifest filename
     * @param asicContent {@link ASiCContent}
     * @return {@link String} archive manifest filename
     */
    protected String getValidArchiveManifestFilename(String archiveManifestFilename, ASiCContent asicContent) {
        archiveManifestFilename = getWithMetaInfFolder(archiveManifestFilename);
        assertFilenameValid(archiveManifestFilename, asicContent.getArchiveManifestDocuments());
        if (!archiveManifestFilename.startsWith(ASiCUtils.META_INF_FOLDER + ASiCUtils.ASIC_ARCHIVE_MANIFEST_FILENAME) ||
                !archiveManifestFilename.endsWith(ASiCUtils.XML_EXTENSION)) {
            throw new IllegalArgumentException(String.format("An archive manifest file within ASiC with CAdES container " +
                    "shall match the template '%s'!", ASiCUtils.META_INF_FOLDER + ASiCUtils.ASIC_ARCHIVE_MANIFEST_FILENAME + "*"
                    + ASiCUtils.XML_EXTENSION));

        } else if (ASiCWithCAdESUtils.DEFAULT_ARCHIVE_MANIFEST_FILENAME.equals(archiveManifestFilename)) {
            throw new IllegalArgumentException(String.format("An archive manifest file within ASiC with CAdES container " +
                    "cannot be moved to a file with name '%s'!", ASiCWithCAdESUtils.DEFAULT_ARCHIVE_MANIFEST_FILENAME));
        }
        return archiveManifestFilename;
    }

}
