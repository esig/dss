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
package eu.europa.esig.dss.asic.xades.merge;

import eu.europa.esig.dss.asic.common.ASiCContent;
import eu.europa.esig.dss.asic.common.ASiCUtils;
import eu.europa.esig.dss.asic.common.ZipUtils;
import eu.europa.esig.dss.asic.common.validation.ASiCManifestParser;
import eu.europa.esig.dss.asic.xades.signature.asice.ASiCEWithXAdESManifestBuilder;
import eu.europa.esig.dss.asic.xades.validation.ASiCEWithXAdESManifestParser;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.spi.exception.IllegalInputException;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.ManifestEntry;
import eu.europa.esig.dss.model.ManifestFile;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.xades.DSSXMLUtils;
import eu.europa.esig.dss.xades.validation.XAdESSignature;
import eu.europa.esig.dss.xades.validation.XMLDocumentAnalyzer;
import eu.europa.esig.dss.xml.utils.DomUtils;
import org.apache.xml.security.signature.Reference;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * This class is used to merge ASiC-E with XAdES containers.
 *
 */
public class ASiCEWithXAdESContainerMerger extends AbstractASiCWithXAdESContainerMerger {

    /**
     * Empty constructor
     */
    ASiCEWithXAdESContainerMerger() {
        // empty
    }

    /**
     * This constructor is used to create an ASiC-E With XAdES container merger from provided container documents
     *
     * @param containers {@link DSSDocument}s representing containers to be merged
     */
    public ASiCEWithXAdESContainerMerger(DSSDocument... containers) {
        super(containers);
    }

    /**
     * This constructor is used to create an ASiC-E With XAdES from to given {@code ASiCContent}s
     *
     * @param asicContents {@link ASiCContent}s to be merged
     */
    public ASiCEWithXAdESContainerMerger(ASiCContent... asicContents) {
        super(asicContents);
    }

    @Override
    protected boolean isSupported(DSSDocument container) {
        return super.isSupported(container) && (!ASiCUtils.isASiCSContainer(container) ||
                (doesNotContainSignatures(container) && doesNotContainEvidenceRecords(container)));
    }

    private boolean doesNotContainSignatures(DSSDocument container) {
        List<String> entryNames = ZipUtils.getInstance().extractEntryNames(container);
        return !ASiCUtils.filesContainSignatures(entryNames);
    }

    private boolean doesNotContainEvidenceRecords(DSSDocument container) {
        List<String> entryNames = ZipUtils.getInstance().extractEntryNames(container);
        return !ASiCUtils.filesContainEvidenceRecords(entryNames);
    }

    @Override
    protected boolean isSupported(ASiCContent asicContent) {
        return super.isSupported(asicContent) && (!ASiCUtils.isASiCSContainer(asicContent) ||
                (doesNotContainSignatures(asicContent) && doesNotContainEvidenceRecords(asicContent)));
    }

    private boolean doesNotContainSignatures(ASiCContent asicContent) {
        return Utils.isCollectionEmpty(asicContent.getSignatureDocuments());
    }

    private boolean doesNotContainEvidenceRecords(ASiCContent asicContent) {
        return Utils.isCollectionEmpty(asicContent.getEvidenceRecordDocuments());
    }

    @Override
    protected ASiCContainerType getTargetASiCContainerType() {
        return ASiCContainerType.ASiC_E;
    }

    @Override
    protected void ensureContainerContentAllowMerge() {
        if (Arrays.stream(asicContents).allMatch(asicContent -> Utils.isCollectionEmpty(asicContent.getSignatureDocuments()) &&
                Utils.isCollectionEmpty(asicContent.getEvidenceRecordDocuments()))) {
            return; // no signatures and evidence records -> can merge
        }
        if (Arrays.stream(asicContents).anyMatch(asicContent -> Utils.isCollectionNotEmpty(asicContent.getTimestampDocuments()))) {
            throw new UnsupportedOperationException("Unable to merge ASiC-E with XAdES containers. " +
                    "One of the containers contains a detached timestamp!");
        }

        Arrays.stream(asicContents).forEach(asicContent -> assertEvidenceRecordDocumentNameValid(asicContent.getEvidenceRecordDocuments()));
    }

    private void assertEvidenceRecordDocumentNameValid(List<DSSDocument> evidenceRecordDocuments) {
        if (Utils.isCollectionNotEmpty(evidenceRecordDocuments)) {
            String evidenceRecordDocumentName = null;
            for (DSSDocument evidenceRecordDocument : evidenceRecordDocuments) {
                if (!ASiCUtils.EVIDENCE_RECORD_XML.equals(evidenceRecordDocument.getName()) &&
                        !ASiCUtils.EVIDENCE_RECORD_ERS.equals(evidenceRecordDocument.getName())) {
                    throw new UnsupportedOperationException("Unable to merge ASiC-E with XAdES containers. " +
                            "The evidence record document in one of the containers has invalid naming!");
                }
                if (evidenceRecordDocumentName == null) {
                    evidenceRecordDocumentName = evidenceRecordDocument.getName();
                } else if (!evidenceRecordDocumentName.equals(evidenceRecordDocument.getName())) {
                    throw new UnsupportedOperationException("Unable to merge ASiC-E with XAdES containers. " +
                            "The evidence record documents have conflicting names within containers!");
                }
            }
        }
    }

    @Override
    protected void ensureSignaturesAllowMerge() {
        if (Arrays.stream(asicContents).filter(asicContent -> Utils.isCollectionNotEmpty(asicContent.getSignatureDocuments()) ||
                Utils.isCollectionNotEmpty(asicContent.getEvidenceRecordDocuments())).count() <= 1) {
            // no signatures or evidence records in all containers except maximum one. Can merge.
            return;
        }

        List<String> coveredDocumentNames = getCoveredDocumentNames();
        if (Arrays.stream(asicContents).anyMatch(asicContent -> doCoverManifest(coveredDocumentNames)) &&
                !sameSignedDocuments()) {
            throw new UnsupportedOperationException("Unable to merge ASiC-E with XAdES containers. " +
                    "manifest.xml is signed or covered and the signer data does not match between containers!");
        }

        List<String> signatureNames = getAllSignatureDocumentNames();
        List<String> conflictingSignatureDocumentNames = getConflictingDocumentNames(signatureNames);
        if (Utils.isCollectionNotEmpty(conflictingSignatureDocumentNames)) {
            for (String signatureDocumentName : conflictingSignatureDocumentNames) {
                if (coveredDocumentNames.contains(signatureDocumentName) && !isSameDocumentContent(signatureDocumentName)) {
                    throw new UnsupportedOperationException("Unable to merge ASiC-E with XAdES containers. " +
                            "A signature is covered by another document, while having same signature names in both containers!");
                }
            }
            ensureSignatureNamesDiffer();
        }

        List<String> evidenceRecordManifestDocumentNames = getAllEvidenceRecordManifestDocumentNames();
        List<String> conflictingEvidenceRecordManifestNames = getConflictingDocumentNames(evidenceRecordManifestDocumentNames);
        if (Utils.isCollectionNotEmpty(conflictingEvidenceRecordManifestNames)) {
            for (String evidenceRecordManifestName : conflictingEvidenceRecordManifestNames) {
                if (coveredDocumentNames.contains(evidenceRecordManifestName) && !isSameDocumentContent(evidenceRecordManifestName)) {
                    throw new UnsupportedOperationException("Unable to merge ASiC-E with XAdES containers. " +
                            "An evidence record manifest is covered by another document, while having same signature names in both containers!");
                }
            }
            ensureEvidenceRecordManifestNamesDiffer();
        }

        // Create a merged manifest.xml file
        DSSDocument newManifest = createNewManifest();
        for (ASiCContent asicContent : asicContents) {
            asicContent.setManifestDocuments(Collections.singletonList(newManifest));
        }
    }

    private boolean isSameDocumentContent(String documentName) {
        byte[] digestValue = null;
        for (ASiCContent asicContent : asicContents) {
            DSSDocument document = DSSUtils.getDocumentWithName(asicContent.getAllDocuments(), documentName);
            byte[] currentDocumentDigestValue = document.getDigestValue(DEFAULT_DIGEST_ALGORITHM);
            if (digestValue == null) {
                digestValue = currentDocumentDigestValue;
            } else if (!Arrays.equals(digestValue, currentDocumentDigestValue)) {
                return false;
            }
        }
        return true;
    }

    private List<String> getCoveredDocumentNames() {
        final List<String> result = new ArrayList<>();
        for (ASiCContent asicContent : asicContents) {
            for (DSSDocument signatureDocument : asicContent.getSignatureDocuments()) {
                XMLDocumentAnalyzer documentValidator = new XMLDocumentAnalyzer(signatureDocument);
                for (AdvancedSignature signature : documentValidator.getSignatures()) {
                    result.addAll(getCoveredDocumentNames((XAdESSignature) signature));
                }
            }
            for (DSSDocument manifestDocument : asicContent.getEvidenceRecordManifestDocuments()) {
                ManifestFile manifestFile = ASiCManifestParser.getManifestFile(manifestDocument);
                if (manifestFile != null) {
                    for (ManifestEntry manifestEntry : manifestFile.getEntries()) {
                        result.add(manifestEntry.getUri());
                    }
                }
            }
        }
        return result;
    }

    private List<String> getCoveredDocumentNames(XAdESSignature signature) {
        final List<String> result = new ArrayList<>();
        for (Reference reference : signature.getReferences()) {
            String referenceURI = DSSXMLUtils.getReferenceURI(reference);
            if (!DomUtils.startsFromHash(referenceURI) && !DomUtils.isXPointerQuery(referenceURI)) {
                result.add(referenceURI);
            }
        }
        return result;
    }

    private boolean doCoverManifest(List<String> documentNames) {
        return documentNames.contains(ASiCUtils.ASICE_METAINF_MANIFEST);
    }

    private boolean sameSignedDocuments() {
        Set<String> signedDocumentNames = null;
        for (ASiCContent asicContent : asicContents) {
            Set<String> currentSignedDocumentNames = new HashSet<>(DSSUtils.getDocumentNames(asicContent.getSignedDocuments()));
            if (signedDocumentNames == null) {
                signedDocumentNames = currentSignedDocumentNames;
            } else if (!signedDocumentNames.equals(currentSignedDocumentNames)) {
                return false;
            }
        }
        return true;
    }

    private List<String> getAllSignatureDocumentNames() {
        List<String> signatureDocumentNames = new ArrayList<>();
        for (ASiCContent asicContent : asicContents) {
            signatureDocumentNames.addAll(DSSUtils.getDocumentNames(asicContent.getSignatureDocuments()));
        }
        return signatureDocumentNames;
    }

    private List<String> getAllEvidenceRecordManifestDocumentNames() {
        List<String> erManifestDocumentNames = new ArrayList<>();
        for (ASiCContent asicContent : asicContents) {
            erManifestDocumentNames.addAll(DSSUtils.getDocumentNames(asicContent.getEvidenceRecordManifestDocuments()));
        }
        return erManifestDocumentNames;
    }

    private List<String> getConflictingDocumentNames(List<String> documentNames) {
        final List<String> result = new ArrayList<>();
        for (String signatureDocumentName : documentNames) {
            if (Collections.frequency(documentNames, signatureDocumentName) > 1) {
                result.add(signatureDocumentName);
            }
        }
        return result;
    }

    private DSSDocument createNewManifest() {
        List<ManifestEntry> manifestEntries = new ArrayList<>();
        List<String> addedFileNames = new ArrayList<>();

        ASiCContent mergedContent = createEmptyContainer();
        for (ASiCContent asicContent : asicContents) {
            List<DSSDocument> manifestDocuments = asicContent.getManifestDocuments();
            mergedContent.getManifestDocuments().addAll(manifestDocuments);

            for (ManifestEntry entry : getManifestFileEntries(manifestDocuments)) {
                if (!addedFileNames.contains(entry.getUri())) {
                    manifestEntries.add(entry);
                    addedFileNames.add(entry.getUri());
                }
            }
            List<DSSDocument> signedDocuments = asicContent.getSignedDocuments();
            for (ManifestEntry entry : ASiCUtils.toSimpleManifestEntries(signedDocuments)) {
                if (!addedFileNames.contains(entry.getUri())) {
                    manifestEntries.add(entry);
                    addedFileNames.add(entry.getUri());
                }
            }
        }

        return createNewManifestXml(manifestEntries, mergedContent);
    }

    private List<ManifestEntry> getManifestFileEntries(List<DSSDocument> manifestDocuments) {
        if (Utils.isCollectionEmpty(manifestDocuments)) {
            return Collections.emptyList();

        } else if (Utils.collectionSize(manifestDocuments) > 1) {
            throw new IllegalInputException("One of the containers contain multiple manifest files!");

        } else {
            DSSDocument manifestDocument = manifestDocuments.get(0);
            if (!ASiCUtils.ASICE_METAINF_MANIFEST.equals(manifestDocument.getName())) {
                throw new IllegalInputException(String.format("A manifest file shall have a name '%s'.",
                        ASiCUtils.ASICE_METAINF_MANIFEST));
            }

            ASiCEWithXAdESManifestParser parser = new ASiCEWithXAdESManifestParser(manifestDocument);
            ManifestFile manifest = parser.getManifest();
            return manifest.getEntries();
        }
    }

    private DSSDocument createNewManifestXml(List<ManifestEntry> manifestEntries, ASiCContent asicContent) {
        return new ASiCEWithXAdESManifestBuilder().setEntries(manifestEntries)
                .setManifestFilename(asicFilenameFactory.getManifestFilename(asicContent)).build();
    }

    private void ensureSignatureNamesDiffer() {
        Set<String> usedSignatureNames = new HashSet<>();
        ASiCContent mergedASiCContent = createEmptyContainer();
        for (ASiCContent asicContent : asicContents) {
            mergedASiCContent.getSignatureDocuments().addAll(asicContent.getSignatureDocuments());
        }

        for (ASiCContent asicContent : asicContents) {
            List<DSSDocument> signatureDocuments = asicContent.getSignatureDocuments();
            for (DSSDocument signatureDocument : signatureDocuments) {
                if (usedSignatureNames.contains(signatureDocument.getName())) {
                    String newSignatureName = asicFilenameFactory.getSignatureFilename(mergedASiCContent);
                    signatureDocument.setName(newSignatureName);
                }
                usedSignatureNames.add(signatureDocument.getName());
            }
        }
    }

    private void ensureEvidenceRecordManifestNamesDiffer() {
        final Set<String> usedNames = new HashSet<>();
        ASiCContent mergedASiCContent = createEmptyContainer();
        for (ASiCContent asicContent : asicContents) {
            mergedASiCContent.getEvidenceRecordManifestDocuments().addAll(asicContent.getEvidenceRecordManifestDocuments());
        }

        for (ASiCContent asicContent : asicContents) {
            List<DSSDocument> evidenceRecordManifestDocuments = asicContent.getEvidenceRecordManifestDocuments();
            for (DSSDocument evidenceRecordManifest : evidenceRecordManifestDocuments) {
                if (usedNames.contains(evidenceRecordManifest.getName())) {
                    String newSignatureName = asicFilenameFactory.getEvidenceRecordManifestFilename(mergedASiCContent);
                    evidenceRecordManifest.setName(newSignatureName);
                }
                usedNames.add(evidenceRecordManifest.getName());
            }
        }
    }

}
