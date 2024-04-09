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
package eu.europa.esig.dss.asic.cades.merge;

import eu.europa.esig.dss.asic.cades.validation.ASiCWithCAdESUtils;
import eu.europa.esig.dss.asic.common.ASiCContent;
import eu.europa.esig.dss.asic.common.ASiCUtils;
import eu.europa.esig.dss.asic.common.ZipUtils;
import eu.europa.esig.dss.asic.common.validation.ASiCManifestParser;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.exception.IllegalInputException;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;

/**
 * This class is used to merge ASiC-E with CAdES containers.
 *
 */
public class ASiCEWithCAdESContainerMerger extends AbstractASiCWithCAdESContainerMerger {

    /**
     * Empty constructor
     */
    ASiCEWithCAdESContainerMerger() {
        // empty
    }

    /**
     * This constructor is used to create an ASiC-E With CAdES container merger from provided container documents
     *
     * @param containers {@link DSSDocument}s representing containers to be merged
     */
    public ASiCEWithCAdESContainerMerger(DSSDocument... containers) {
        super(containers);
    }

    /**
     * This constructor is used to create an ASiC-E With CAdES from to given {@code ASiCContent}s
     *
     * @param asicContents {@link ASiCContent}s to be merged
     */
    public ASiCEWithCAdESContainerMerger(ASiCContent... asicContents) {
        super(asicContents);
    }

    @Override
    protected boolean isSupported(DSSDocument container) {
        return super.isSupported(container) && (!ASiCUtils.isASiCSContainer(container) || doesNotContainSignatures(container));
    }

    private boolean doesNotContainSignatures(DSSDocument container) {
        List<String> entryNames = ZipUtils.getInstance().extractEntryNames(container);
        return !ASiCUtils.filesContainSignatures(entryNames);
    }

    @Override
    protected boolean isSupported(ASiCContent asicContent) {
        return super.isSupported(asicContent) && (!ASiCUtils.isASiCSContainer(asicContent) || doesNotContainSignatures(asicContent));
    }

    private boolean doesNotContainSignatures(ASiCContent asicContent) {
        return Utils.isCollectionEmpty(asicContent.getSignatureDocuments());
    }

    @Override
    protected ASiCContainerType getTargetASiCContainerType() {
        return ASiCContainerType.ASiC_E;
    }

    @Override
    protected void ensureContainerContentAllowMerge() {
        // no checks available
    }

    @Override
    protected void ensureSignaturesAllowMerge() {
        if (Arrays.stream(asicContents).filter(asicContent -> Utils.isCollectionNotEmpty(asicContent.getSignatureDocuments()) ||
                Utils.isCollectionNotEmpty(asicContent.getTimestampDocuments())).count() <= 1) {
            // no signatures nor timestamps in all containers except maximum one. Can merge.
            return;
        }

        ensureSignatureDocumentsValid();
        ensureManifestDocumentsValid();
    }

    private void ensureSignatureDocumentsValid() {
        List<String> mergedSignatureNames = new ArrayList<>();
        List<ASiCContent> asicContentsToProcess = new ArrayList<>(Arrays.asList(asicContents));
        Iterator<ASiCContent> iterator = asicContentsToProcess.iterator();
        while (iterator.hasNext()) {
            ASiCContent asicContent = iterator.next();
            iterator.remove(); // remove entry to avoid recursive comparison

            List<DSSDocument> signatureDocumentList = new ArrayList<>(asicContent.getSignatureDocuments());
            for (DSSDocument signatureDocument : signatureDocumentList) {
                if (mergedSignatureNames.contains(signatureDocument.getName())) {
                    continue;
                }

                List<DSSDocument> signaturesToMerge = getSignatureDocumentsToBeMerged(asicContent, signatureDocument, asicContentsToProcess);
                if (Utils.isCollectionNotEmpty(signaturesToMerge)) {
                    signaturesToMerge.add(signatureDocument);
                    mergedSignatureNames.add(signatureDocument.getName());

                    DSSDocument signaturesCms = mergeCmsSignatures(signaturesToMerge);
                    updateMergedSignatureInContainers(signaturesCms);
                }

            }
        }
    }

    private List<DSSDocument> getSignatureDocumentsToBeMerged(ASiCContent currentASiCContent,
                                                              DSSDocument currentSignatureDocument,
                                                              List<ASiCContent> asicContentList) {
        if (currentSignatureDocument.getName() == null) {
            throw new IllegalInputException("Name shall be provided for a document!");
        }
        DSSDocument manifest = ASiCManifestParser.getLinkedManifest(
                currentASiCContent.getAllManifestDocuments(), currentSignatureDocument.getName());
        if (manifest == null) {
            throw new UnsupportedOperationException(String.format("Unable to merge ASiC-E with CAdES containers. " +
                    "A signature with filename '%s' does not have a corresponding manifest file!", currentSignatureDocument.getName()));
        }

        List<DSSDocument> result = new ArrayList<>();

        for (ASiCContent asicContentToCompare : asicContentList) {
            DSSDocument signatureToCompare = DSSUtils.getDocumentWithName(
                    asicContentToCompare.getSignatureDocuments(), currentSignatureDocument.getName());
            if (signatureToCompare != null) {
                DSSDocument manifestToCompare = ASiCManifestParser.getLinkedManifest(
                        asicContentToCompare.getAllManifestDocuments(), signatureToCompare.getName());
                if (manifestToCompare == null) {
                    throw new UnsupportedOperationException(String.format("Unable to merge ASiC-E with CAdES containers. " +
                            "A signature with filename '%s' does not have a corresponding manifest file!", signatureToCompare.getName()));

                } else if (ASiCWithCAdESUtils.isCoveredByManifest(currentASiCContent.getAllManifestDocuments(), currentSignatureDocument.getName()) ||
                        ASiCWithCAdESUtils.isCoveredByManifest(asicContentToCompare.getAllManifestDocuments(), signatureToCompare.getName())) {
                    throw new UnsupportedOperationException(String.format("Unable to merge ASiC-E with CAdES containers. " +
                            "A signature with name '%s' in a container is covered by a manifest!", currentSignatureDocument.getName()));

                } else if (manifest.getName().equals(manifestToCompare.getName()) &&
                        Arrays.equals(manifest.getDigestValue(DEFAULT_DIGEST_ALGORITHM), manifestToCompare.getDigestValue(DEFAULT_DIGEST_ALGORITHM))) {
                    result.add(signatureToCompare);

                } else {
                    throw new UnsupportedOperationException(String.format("Unable to merge ASiC-E with CAdES containers. " +
                            "Signatures with filename '%s' sign different manifests!", currentSignatureDocument.getName()));
                }
            }
        }

        return result;
    }

    private void updateMergedSignatureInContainers(DSSDocument mergedCmsSignature) {
        for (ASiCContent asicContent : asicContents) {
            if (DSSUtils.getDocumentNames(asicContent.getSignatureDocuments()).contains(mergedCmsSignature.getName())) {
                ASiCUtils.addOrReplaceDocument(asicContent.getSignatureDocuments(), mergedCmsSignature);
            }
        }
    }

    private void ensureManifestDocumentsValid() {
        ASiCContent mergedASiCContent = createEmptyContainer();
        for (ASiCContent asicContent : asicContents) {
            mergedASiCContent.getManifestDocuments().addAll(asicContent.getManifestDocuments());
            mergedASiCContent.getArchiveManifestDocuments().addAll(asicContent.getArchiveManifestDocuments());
        }

        List<ASiCContent> asicContentsToProcess = new ArrayList<>(Arrays.asList(asicContents));
        Iterator<ASiCContent> iterator = asicContentsToProcess.iterator();
        while (iterator.hasNext()) {
            ASiCContent asicContent = iterator.next();
            iterator.remove();
            for (DSSDocument manifest : asicContent.getManifestDocuments()) {
                for (ASiCContent currentASiCContent : asicContentsToProcess) {
                    for (DSSDocument currentManifest : currentASiCContent.getManifestDocuments()) {
                        if (manifest.getName() != null && manifest.getName().equals(currentManifest.getName())) {
                            if (Arrays.equals(manifest.getDigestValue(DEFAULT_DIGEST_ALGORITHM), currentManifest.getDigestValue(DEFAULT_DIGEST_ALGORITHM))) {
                                // continue

                            } else if (ASiCWithCAdESUtils.isCoveredByManifest(asicContent.getAllManifestDocuments(), manifest.getName()) ||
                                    ASiCWithCAdESUtils.isCoveredByManifest(currentASiCContent.getAllManifestDocuments(), currentManifest.getName())) {
                                throw new UnsupportedOperationException(String.format("Unable to merge ASiC-E with CAdES containers. " +
                                        "A manifest with name '%s' in a container is covered by another manifest!", currentManifest.getName()));

                            } else {
                                String newManifestName = asicFilenameFactory.getManifestFilename(mergedASiCContent);
                                currentManifest.setName(newManifestName);
                            }
                        }
                    }
                }
            }
            for (DSSDocument manifest : asicContent.getArchiveManifestDocuments()) {
                for (ASiCContent currentASiCContent : asicContentsToProcess) {
                    for (DSSDocument currentManifest : currentASiCContent.getArchiveManifestDocuments()) {
                        if (manifest.getName() != null && manifest.getName().equals(currentManifest.getName())) {
                            if (Arrays.equals(manifest.getDigestValue(DEFAULT_DIGEST_ALGORITHM), currentManifest.getDigestValue(DEFAULT_DIGEST_ALGORITHM))) {
                                // continue

                            } else if (ASiCWithCAdESUtils.isCoveredByManifest(asicContent.getAllManifestDocuments(), manifest.getName()) ||
                                    ASiCWithCAdESUtils.isCoveredByManifest(currentASiCContent.getAllManifestDocuments(), currentManifest.getName())) {
                                throw new UnsupportedOperationException(String.format("Unable to merge ASiC-E with CAdES containers. " +
                                        "A manifest with name '%s' in a container is covered by another manifest!", currentManifest.getName()));

                            } else {
                                String newManifestName = asicFilenameFactory.getArchiveManifestFilename(mergedASiCContent);
                                currentManifest.setName(newManifestName);
                            }
                        }
                    }
                }
            }
        }
    }

}
