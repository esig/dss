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
package eu.europa.esig.dss.asic.cades;

import eu.europa.esig.dss.asic.cades.validation.ASiCWithCAdESUtils;
import eu.europa.esig.dss.asic.common.ASiCContent;
import eu.europa.esig.dss.asic.common.ASiCUtils;
import eu.europa.esig.dss.asic.common.AbstractASiCFilenameFactory;
import eu.europa.esig.dss.enumerations.EvidenceRecordTypeEnum;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;

import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

/**
 * This class provides a default implementation of {@code ASiCWithCAdESFilenameFactory}
 * used within basic configuration of DSS for creation of filenames for new container entries.
 *
 */
public class DefaultASiCWithCAdESFilenameFactory extends AbstractASiCFilenameFactory implements ASiCWithCAdESFilenameFactory {

    private static final long serialVersionUID = -4144978379851552021L;

    /**
     * Default constructor
     */
    public DefaultASiCWithCAdESFilenameFactory() {
        // empty
    }

    @Override
    public String getSignatureFilename(ASiCContent asicContent) {
        assertASiCContentIsValid(asicContent);
        if (ASiCUtils.isASiCSContainer(asicContent)) {
            return ASiCUtils.SIGNATURE_P7S; // "META-INF/signature.p7s";
        } else {
            List<String> existingSignatureNames = DSSUtils.getDocumentNames(asicContent.getSignatureDocuments());
            // "META-INF/signature*.p7s"
            return getNextAvailableDocumentName(ASiCUtils.ASICE_METAINF_CADES_SIGNATURE, existingSignatureNames);
        }
    }

    @Override
    public String getTimestampFilename(ASiCContent asicContent) {
        assertASiCContentIsValid(asicContent);
        if (ASiCUtils.isASiCSContainer(asicContent) && Utils.isCollectionEmpty(asicContent.getTimestampDocuments())) {
            return ASiCUtils.TIMESTAMP_TST; // "META-INF/timestamp.tst";
        } else {
            List<String> existingTimestampNames = DSSUtils.getDocumentNames(asicContent.getTimestampDocuments());
            // "META-INF/timestamp*.tst"
            return getNextAvailableDocumentName(ASiCUtils.ASICE_METAINF_CADES_TIMESTAMP, existingTimestampNames);
        }
    }

    @Override
    public String getManifestFilename(ASiCContent asicContent) {
        assertASiCContentIsValid(asicContent);
        if (ASiCUtils.isASiCEContainer(asicContent)) {
            List<String> existingManifestNames = DSSUtils.getDocumentNames(asicContent.getManifestDocuments());
            // "META-INF/ASiCManifest*.xml"
            return getNextAvailableDocumentName(ASiCUtils.ASICE_METAINF_CADES_MANIFEST, existingManifestNames);
        } else {
            throw new UnsupportedOperationException("Manifest is not applicable for ASiC-S with CAdES container!");
        }
    }

    @Override
    public String getArchiveManifestFilename(ASiCContent asicContent) {
        assertASiCContentIsValid(asicContent);
        if (ASiCUtils.isASiCEContainer(asicContent) || Utils.isCollectionNotEmpty(asicContent.getTimestampDocuments())) {
            List<String> existingArchiveManifestNames = DSSUtils.getDocumentNames(asicContent.getArchiveManifestDocuments());
            existingArchiveManifestNames.remove(ASiCWithCAdESUtils.DEFAULT_ARCHIVE_MANIFEST_FILENAME);
            // "META-INF/ASiCArchiveManifest*.xml"
            return getNextAvailableDocumentName(ASiCUtils.ASICE_METAINF_CADES_ARCHIVE_MANIFEST, existingArchiveManifestNames);
        } else {
            throw new UnsupportedOperationException("Manifest is not applicable for ASiC-S with CAdES container!");
        }
    }

    @Override
    public String getDataPackageFilename(ASiCContent asicContent) {
        return ASiCUtils.PACKAGE_ZIP; // "package.zip"
    }

    @Override
    public String getEvidenceRecordFilename(ASiCContent asicContent, EvidenceRecordTypeEnum evidenceRecordType) {
        Objects.requireNonNull(evidenceRecordType, "EvidenceRecordType shall be defined!");
        assertASiCContentIsValid(asicContent);
        if (ASiCUtils.isASiCSContainer(asicContent)) {
            switch (evidenceRecordType) {
                case XML_EVIDENCE_RECORD:
                    return ASiCUtils.EVIDENCE_RECORD_XML; // "META-INF/evidencerecord.xml"
                case ASN1_EVIDENCE_RECORD:
                    return ASiCUtils.EVIDENCE_RECORD_ERS;
                default:
                    throw new UnsupportedOperationException(
                            String.format("The Evidence Record Type '%s' is not supported!", evidenceRecordType));
            }
        } else { // ASiC-E
            List<String> existingEvidenceRecordNames = DSSUtils.getDocumentNames(asicContent.getEvidenceRecordDocuments());
            String targetEvidenceRecordName;
            switch (evidenceRecordType) {
                case XML_EVIDENCE_RECORD:
                    targetEvidenceRecordName = ASiCUtils.ASICE_METAINF_CADES_EVIDENCE_RECORD_XML; // "META-INF/evidencerecord*.xml"
                    existingEvidenceRecordNames = existingEvidenceRecordNames.stream()
                            .filter(n -> n.endsWith(ASiCUtils.XML_EXTENSION)).collect(Collectors.toList());
                    break;
                case ASN1_EVIDENCE_RECORD:
                    targetEvidenceRecordName = ASiCUtils.ASICE_METAINF_CADES_EVIDENCE_RECORD_ASN1; // "META-INF/evidencerecord*.ers"
                    existingEvidenceRecordNames = existingEvidenceRecordNames.stream()
                            .filter(n -> n.endsWith(ASiCUtils.ER_ASN1_EXTENSION)).collect(Collectors.toList());
                    break;
                default:
                    throw new UnsupportedOperationException(
                            String.format("The Evidence Record Type '%s' is not supported!", evidenceRecordType));
            }
            return getNextAvailableDocumentName(targetEvidenceRecordName, existingEvidenceRecordNames);
        }
    }

    @Override
    public String getEvidenceRecordManifestFilename(ASiCContent asicContent) {
        assertASiCContentIsValid(asicContent);
        List<String> existingManifestNames = DSSUtils.getDocumentNames(asicContent.getEvidenceRecordManifestDocuments());
        // "META-INF/ASiCEvidenceRecordManifest*.xml"
        return getNextAvailableDocumentName(ASiCUtils.ASICE_METAINF_EVIDENCE_RECORD_MANIFEST, existingManifestNames);
    }

}
