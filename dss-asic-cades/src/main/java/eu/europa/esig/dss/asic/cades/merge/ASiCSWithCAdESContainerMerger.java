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
package eu.europa.esig.dss.asic.cades.merge;

import eu.europa.esig.dss.asic.common.ASiCContent;
import eu.europa.esig.dss.asic.common.ASiCUtils;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.utils.Utils;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * This class is used to merge ASiC-S with CAdES containers.
 *
 */
public class ASiCSWithCAdESContainerMerger extends AbstractASiCWithCAdESContainerMerger {

    /**
     * Empty constructor
     */
    ASiCSWithCAdESContainerMerger() {
        // empty
    }

    /**
     * This constructor is used to create an ASiC-S With CAdES container merger from provided container documents
     *
     * @param containers {@link DSSDocument}s representing containers to be merged
     */
    public ASiCSWithCAdESContainerMerger(DSSDocument... containers) {
        super(containers);
    }

    /**
     * This constructor is used to create an ASiC-S With CAdES from to given {@code ASiCContent}s
     *
     * @param asicContents {@link ASiCContent}s to be merged
     */
    public ASiCSWithCAdESContainerMerger(ASiCContent... asicContents) {
        super(asicContents);
    }

    @Override
    public boolean isSupported(DSSDocument container) {
        return super.isSupported(container) && !ASiCUtils.isASiCEContainer(container);
    }

    @Override
    public boolean isSupported(ASiCContent asicContent) {
        return super.isSupported(asicContent) && !ASiCUtils.isASiCEContainer(asicContent);
    }

    @Override
    protected ASiCContainerType getTargetASiCContainerType() {
        return ASiCContainerType.ASiC_S;
    }

    @Override
    protected void ensureContainerContentAllowMerge() {
        if (Arrays.stream(asicContents).allMatch(asicContent -> Utils.isCollectionEmpty(asicContent.getSignatureDocuments()) &&
                Utils.isCollectionEmpty(asicContent.getTimestampDocuments()) && Utils.isCollectionEmpty(asicContent.getEvidenceRecordDocuments()))) {
            return; // no signatures, timestamps and evidence records -> can merge
        }

        if (Arrays.stream(asicContents).anyMatch(asicContent -> Utils.collectionSize(asicContent.getSignatureDocuments()) +
                Utils.collectionSize(asicContent.getTimestampDocuments()) + Utils.collectionSize(asicContent.getEvidenceRecordDocuments()) > 1)) {
            throw new UnsupportedOperationException("Unable to merge ASiC-S with CAdES containers. " +
                    "One of the containers has more than one signature, timestamp or evidence record documents!");
        }
        if (Arrays.stream(asicContents).anyMatch(asicContent -> Utils.isCollectionNotEmpty(asicContent.getSignatureDocuments())) &&
                (Arrays.stream(asicContents).anyMatch(asicContent -> Utils.isCollectionNotEmpty(asicContent.getTimestampDocuments())) ||
                Arrays.stream(asicContents).anyMatch(asicContent -> Utils.isCollectionNotEmpty(asicContent.getEvidenceRecordDocuments())))) {
            throw new UnsupportedOperationException("Unable to merge ASiC-S with CAdES containers. " +
                    "Only one type of a container is allowed (signature, timestamp or evidence record)!");
        }
        if (Arrays.stream(asicContents).filter(asicContent -> Utils.isCollectionNotEmpty(asicContent.getTimestampDocuments()) ||
                Utils.isCollectionNotEmpty(asicContent.getEvidenceRecordDocuments())).count() > 1) {
            throw new UnsupportedOperationException("Unable to merge ASiC-S with CAdES containers. " +
                    "Timestamp or evidence record containers cannot be merged with the given container type!");
        }

        Arrays.stream(asicContents).forEach(asicContent -> assertSignatureDocumentNameValid(asicContent.getSignatureDocuments()));
        Arrays.stream(asicContents).forEach(asicContent -> assertTimestampDocumentNameValid(asicContent.getTimestampDocuments()));
        Arrays.stream(asicContents).forEach(asicContent -> assertEvidenceRecordDocumentNameValid(asicContent.getEvidenceRecordDocuments()));

        if (Arrays.stream(asicContents).anyMatch(asicContent -> Utils.collectionSize(asicContent.getRootLevelSignedDocuments()) > 1)) {
            throw new UnsupportedOperationException("Unable to merge ASiC-S with CAdES containers. " +
                    "One of the containers has more than one signer documents!");
        }

        if (!checkRootSignerDocumentsNames()) {
            throw new UnsupportedOperationException("Unable to merge ASiC-S with CAdES containers. " +
                    "Signer documents have different names!");
        }
    }

    private void assertSignatureDocumentNameValid(List<DSSDocument> signatureDocuments) {
        if (Utils.isCollectionNotEmpty(signatureDocuments)) {
            for (DSSDocument signatureDocument : signatureDocuments) {
                if (!ASiCUtils.SIGNATURE_P7S.equals(signatureDocument.getName()) ) {
                    throw new UnsupportedOperationException("Unable to merge ASiC-S with CAdES containers. " +
                            "The signature document in one of the containers has invalid naming!");
                }
            }
        }
    }

    private void assertTimestampDocumentNameValid(List<DSSDocument> timestampDocuments) {
        if (Utils.isCollectionNotEmpty(timestampDocuments)) {
            for (DSSDocument tstDocument : timestampDocuments) {
                if (!ASiCUtils.TIMESTAMP_TST.equals(tstDocument.getName())) {
                    throw new UnsupportedOperationException("Unable to merge ASiC-S with CAdES containers. " +
                            "The timestamp document in one of the containers has invalid naming!");
                }
            }
        }
    }

    private void assertEvidenceRecordDocumentNameValid(List<DSSDocument> evidenceRecordDocuments) {
        if (Utils.isCollectionNotEmpty(evidenceRecordDocuments)) {
            String evidenceRecordDocumentName = null;
            for (DSSDocument evidenceRecordDocument : evidenceRecordDocuments) {
                if (!ASiCUtils.EVIDENCE_RECORD_XML.equals(evidenceRecordDocument.getName()) &&
                        !ASiCUtils.EVIDENCE_RECORD_ERS.equals(evidenceRecordDocument.getName())) {
                    throw new UnsupportedOperationException("Unable to merge ASiC-S with CAdES containers. " +
                            "The evidence record document in one of the containers has invalid naming!");
                }
                if (evidenceRecordDocumentName == null) {
                    evidenceRecordDocumentName = evidenceRecordDocument.getName();
                } else if (!evidenceRecordDocumentName.equals(evidenceRecordDocument.getName())) {
                    throw new UnsupportedOperationException("Unable to merge ASiC-S with CAdES containers. " +
                            "The evidence record documents have conflicting names within containers!");
                }
            }
        }
    }

    private boolean checkRootSignerDocumentsNames() {
        String rootSignedDocumentName = null;
        for (ASiCContent asicContent : asicContents) {
            List<DSSDocument> rootLevelSignedDocuments = asicContent.getRootLevelSignedDocuments();
            if (Utils.isCollectionNotEmpty(rootLevelSignedDocuments)) {
                DSSDocument currentSignedDocument = rootLevelSignedDocuments.get(0); // only one shall be present
                if (rootSignedDocumentName == null) {
                    rootSignedDocumentName = currentSignedDocument.getName();
                } else {
                    return rootSignedDocumentName.equals(currentSignedDocument.getName());
                }
            }
        }
        return true;
    }

    @Override
    protected void ensureSignaturesAllowMerge() {
        if (Arrays.stream(asicContents).filter(asicContent ->
                        Utils.isCollectionNotEmpty(asicContent.getSignatureDocuments()) ||
                        Utils.isCollectionNotEmpty(asicContent.getTimestampDocuments()) ||
                        Utils.isCollectionNotEmpty(asicContent.getEvidenceRecordDocuments()))
                .count() <= 1) {
            // one of the containers does not contain a signature document. Can merge.
            return;
        }

        mergeSignatureDocuments();
    }

    private void mergeSignatureDocuments() {
        List<DSSDocument> allSignatureDocuments = getAllSignatureDocuments(asicContents);
        DSSDocument mergedCMSSignaturesDocument = mergeCmsSignatures(allSignatureDocuments);
        for (ASiCContent asicContent : asicContents) {
            asicContent.setSignatureDocuments(Collections.singletonList(mergedCMSSignaturesDocument));
        }
    }

}
