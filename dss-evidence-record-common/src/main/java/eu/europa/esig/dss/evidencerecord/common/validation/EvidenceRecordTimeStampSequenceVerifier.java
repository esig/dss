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
package eu.europa.esig.dss.evidencerecord.common.validation;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSMessageDigest;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.ManifestEntry;
import eu.europa.esig.dss.model.ManifestFile;
import eu.europa.esig.dss.model.ReferenceValidation;
import eu.europa.esig.dss.spi.DSSMessageDigestCalculator;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.evidencerecord.EvidenceRecord;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

/**
 * This class performs a verification of complete Evidence Record Archive Time-Stamp Sequence
 *
 */
public abstract class EvidenceRecordTimeStampSequenceVerifier {

    private static final Logger LOG = LoggerFactory.getLogger(EvidenceRecordTimeStampSequenceVerifier.class);

    /** Evidence record to be validated */
    protected final DefaultEvidenceRecord evidenceRecord;

    /** Contains a list of reference validations performed on the archive data objects */
    private List<ReferenceValidation> referenceValidations;

    /**
     * Evidence record to be validated
     *
     * @param evidenceRecord {@link EvidenceRecord}
     */
    protected EvidenceRecordTimeStampSequenceVerifier(final DefaultEvidenceRecord evidenceRecord) {
        this.evidenceRecord = evidenceRecord;
    }

    /**
     * Gets a list of reference validations
     *
     * @return a list of {@link ReferenceValidation}s
     */
    public List<ReferenceValidation> getReferenceValidations() {
        if (referenceValidations == null) {
            verify();
        }
        return referenceValidations;
    }

    /**
     * Performs verification of the Evidence Record. Generated reference validations and time-stamp tokens
     */
    protected void verify() {
        referenceValidations = new ArrayList<>();

        DSSMessageDigest lastTimeStampHash = DSSMessageDigest.createEmptyDigest();

        boolean firstArchiveTimeStampChain = true;
        List<? extends ArchiveTimeStampChainObject> archiveTimeStampSequence = evidenceRecord.getArchiveTimeStampSequence();
        for (ArchiveTimeStampChainObject archiveTimeStampChain : archiveTimeStampSequence) {
            DigestAlgorithm digestAlgorithm = archiveTimeStampChain.getDigestAlgorithm();
            List<DSSDocument> detachedContents = lastTimeStampHash.isEmpty() ?
                    evidenceRecord.getDetachedContents() : Collections.emptyList();
            DSSMessageDigest lastTimeStampSequenceHash = firstArchiveTimeStampChain ?
            		DSSMessageDigest.createEmptyDigest() : computePrecedingTimeStampSequenceHash(archiveTimeStampChain, detachedContents);

            List<? extends ArchiveTimeStampObject> archiveTimeStamps = archiveTimeStampChain.getArchiveTimeStamps();
            Iterator<? extends ArchiveTimeStampObject> archiveTimeStampsIt = archiveTimeStamps.iterator();
            while (archiveTimeStampsIt.hasNext()) {
                ArchiveTimeStampObject archiveTimeStamp = archiveTimeStampsIt.next();

                List<ReferenceValidation> timestampValidations = new ArrayList<>();
                DSSMessageDigest lastMessageDigest = DSSMessageDigest.createEmptyDigest();

                List<? extends DigestValueGroup> hashTree = getHashTree(archiveTimeStamp.getHashTree(), detachedContents,
                        archiveTimeStampChain, lastTimeStampHash, lastTimeStampSequenceHash);
                for (DigestValueGroup digestValueGroup : hashTree) {
                    // Validation of first HashTree/Sequence
                    if (lastMessageDigest.isEmpty()) {
                        ManifestFile manifestFile = lastTimeStampHash.isEmpty() ?
                                evidenceRecord.getManifestFile() : null;
                        // execute for all time-stamps in order to create reference validations
                        List<ReferenceValidation> archiveDataObjectValidations =
                                validateArchiveDataObjects(digestValueGroup, archiveTimeStampChain, detachedContents, manifestFile);

                        if (!lastTimeStampHash.isEmpty()) {
                            // validate following archive time-stamps
                            timestampValidations = validateArchiveTimeStampDigest(archiveDataObjectValidations, lastTimeStampHash);
                        }
                        // if first time-stamp in a next ArchiveTimeStampChain
                        else if (!lastTimeStampSequenceHash.isEmpty()) {
                            // validate first time-stamp in ArchiveTimeStampChain
                            timestampValidations = validateArchiveTimeStampSequenceDigest(archiveDataObjectValidations, lastTimeStampSequenceHash);
                        }
                        if (manifestFile != null) {
                            archiveDataObjectValidations = validateManifestEntries(archiveDataObjectValidations, manifestFile, firstArchiveTimeStampChain);
                        }

                        if (lastTimeStampHash.isEmpty() && firstArchiveTimeStampChain) {
                            referenceValidations.addAll(archiveDataObjectValidations);
                        }
                    }
                    // Validation of each followingHashTree/Sequence
                    lastMessageDigest = computeDigestValueGroupHash(digestAlgorithm, digestValueGroup, lastMessageDigest);
                }

                // Validate time-stamp
                TimestampToken timestampToken = archiveTimeStamp.getTimestampToken();
                timestampToken.matchData(lastMessageDigest);
                timestampToken.setReferenceValidations(timestampValidations);

                if (archiveTimeStampsIt.hasNext()) {
                    lastTimeStampHash = computeTimeStampHash(digestAlgorithm, archiveTimeStamp, archiveTimeStampChain);
                }
            }

            firstArchiveTimeStampChain = false;
            lastTimeStampHash = DSSMessageDigest.createEmptyDigest();
        }
    }

    /**
     * This method returns a relevant HashTree, and created a "virtual" HashTree when a  HashTree is omitted in the TimeStamp
     *
     * @param originalHashTree a list of {@link DigestValueGroup}, representing an original HashTree extracted from a time-stamp token
     * @param detachedContents a list of {@link DSSDocument}s, provided to the validation as a detached content
     * @param archiveTimeStampChain {@link ArchiveTimeStampChainObject} archive time-stamp chain containing the time-stamp
     * @param lastTimeStampHash {@link DSSMessageDigest} digest of the previous archive-time-stamp, when applicable
     * @param lastTimeStampSequenceHash {@link DSSMessageDigest} digest of the previous archive-time-stamp-sequence, when applicable
     * @return a list of {@link DigestValueGroup}, representing a HashTree to be used for an archive-time-stamp validation
     */
    protected List<? extends DigestValueGroup> getHashTree(
            List<? extends DigestValueGroup> originalHashTree, List<DSSDocument> detachedContents,
            ArchiveTimeStampChainObject archiveTimeStampChain, DSSMessageDigest lastTimeStampHash, DSSMessageDigest lastTimeStampSequenceHash) {
        List<? extends DigestValueGroup> hashTree;
        if (Utils.isCollectionNotEmpty(originalHashTree)) {
            hashTree = new ArrayList<>(originalHashTree);

        } else {
            LOG.info("No hashTree found for time-stamp validation. Use provided data as first level data object.");

            // if hashTree is not present, it means the time-stamp covers a single data object
            final DigestValueGroup digestValueGroup = new DigestValueGroup();

            final List<byte[]> digestValues = new ArrayList<>();
            if (lastTimeStampHash != null && !lastTimeStampHash.isEmpty()) {
                // time-stamp renewal
                digestValues.add(lastTimeStampHash.getValue());

            } else if (lastTimeStampSequenceHash != null && !lastTimeStampSequenceHash.isEmpty()) {
                // HashTree renewal
                digestValues.addAll(getLastTimeStampSequenceHashList(lastTimeStampSequenceHash, detachedContents));

            } else if (Utils.collectionSize(detachedContents) == 1) {
                // Initial time-stamp
                digestValues.add(getDocumentDigest(detachedContents.get(0), archiveTimeStampChain));

            } else {
                LOG.warn("Unable to determine original data object for omitted hashTree. " +
                        "{} documents provided instead of one.", Utils.collectionSize(detachedContents));
                digestValues.add(DSSUtils.EMPTY_BYTE_ARRAY);
            }

            digestValueGroup.setDigestValues(digestValues);

            hashTree = Collections.singletonList(digestValueGroup);
        }

        return hashTree;
    }

    /**
     * Returns a list of hashes computed on a given previous time-stamp sequence hash
     *
     * @param lastTimeStampSequenceHash {@link DSSMessageDigest} of the previous ArchiveTimeStampSequence
     * @param detachedDocuments a list of detached {@link DSSDocument}s
     * @return a list of byte arrays
     */
    protected List<byte[]> getLastTimeStampSequenceHashList(
            DSSMessageDigest lastTimeStampSequenceHash, List<DSSDocument> detachedDocuments) {
        return Collections.singletonList(lastTimeStampSequenceHash.getValue());
    }

    /**
     * Returns digest value for the document
     *
     * @param document {@link DSSDocument} to get digest value for
     * @param archiveTimeStampChain {@link ArchiveTimeStampChainObject} of the current hashtree
     * @return byte array representing document digest
     */
    protected byte[] getDocumentDigest(DSSDocument document, ArchiveTimeStampChainObject archiveTimeStampChain) {
        return Utils.fromBase64(document.getDigest(archiveTimeStampChain.getDigestAlgorithm()));
    }

    /**
     * This method is used to verify presence of ArchiveTimeStamp digests within the reference validation list.
     * If entry is not present, created one, when applicable
     *
     * @param referenceValidations a list of {@link ReferenceValidation}s
     * @param lastTimeStampHash {@link DSSMessageDigest}
     * @return an updated list of {@link ReferenceValidation}s
     */
    protected List<ReferenceValidation> validateArchiveTimeStampDigest(List<ReferenceValidation> referenceValidations,
                                                                     DSSMessageDigest lastTimeStampHash) {
        return validateAdditionalDigest(referenceValidations, lastTimeStampHash, DigestMatcherType.EVIDENCE_RECORD_ARCHIVE_TIME_STAMP);
    }

    /**
     * This method is used to verify presence of ArchiveTimeStampSequence digests within the reference validation list.
     * If entry is not present, created one, when applicable
     *
     * @param referenceValidations a list of {@link ReferenceValidation}s
     * @param lastTimeStampSequenceHashes {@link DSSMessageDigest}
     * @return an updated list of {@link ReferenceValidation}s
     */
    protected List<ReferenceValidation> validateArchiveTimeStampSequenceDigest(List<ReferenceValidation> referenceValidations,
                                                                             DSSMessageDigest lastTimeStampSequenceHashes) {
        return validateAdditionalDigest(referenceValidations, lastTimeStampSequenceHashes, DigestMatcherType.EVIDENCE_RECORD_ARCHIVE_TIME_STAMP_SEQUENCE);
    }
    
    private List<ReferenceValidation> validateAdditionalDigest(List<ReferenceValidation> referenceValidations,
                                                               DSSMessageDigest messageDigest, DigestMatcherType type) {
        List<ReferenceValidation> invalidReferences = referenceValidations.stream().filter(r -> !r.isIntact()).collect(Collectors.toList());
        for (ReferenceValidation reference : invalidReferences) {
            if (reference.getDigest() != null && Arrays.equals(messageDigest.getValue(), reference.getDigest().getValue())) {
                reference.setName(null);
                reference.setType(type);
                reference.setFound(true);
                reference.setIntact(true);
                return referenceValidations;
            }
        }
        // If one invalid reference and hash does not match -> change type
        if (Utils.collectionSize(invalidReferences) == 1) {
            ReferenceValidation reference = invalidReferences.iterator().next();
            reference.setType(type);
            reference.setFound(!messageDigest.isEmpty());
        }
        return referenceValidations;
    }

    private List<ReferenceValidation> validateManifestEntries(List<ReferenceValidation> referenceValidations, ManifestFile manifestFile, boolean firstTimeStamp) {
        if (manifestFile == null) {
            return referenceValidations;
        }

        // create empty ReferenceValidations for not found manifest entries, when applicable
        List<String> foundDocumentNames = referenceValidations.stream().map(ReferenceValidation::getName).filter(Objects::nonNull).collect(Collectors.toList());
        if (Utils.collectionSize(manifestFile.getEntries()) > Utils.collectionSize(foundDocumentNames)) {
            List<ReferenceValidation> failedReferences = referenceValidations.stream().filter(r -> !r.isIntact()).collect(Collectors.toList());
            if (Utils.collectionSize(manifestFile.getEntries()) - Utils.collectionSize(foundDocumentNames) >= Utils.collectionSize(failedReferences)) {
                // remove failed references
                for (ReferenceValidation reference : failedReferences) {
                    referenceValidations.remove(reference);
                }
            }
            // add references from a manifest
            for (ManifestEntry manifestEntry : manifestFile.getEntries()) {
                if (!foundDocumentNames.contains(manifestEntry.getFileName())) {
                    LOG.warn("Manifest entry with name '{}' was not found within evidence record data objects!", manifestEntry.getFileName());

                    DSSDocument matchingDocument = getMatchingDocument(manifestEntry, evidenceRecord.getDetachedContents());

                    ReferenceValidation referenceValidation = new ReferenceValidation();
                    referenceValidation.setType(DigestMatcherType.EVIDENCE_RECORD_ARCHIVE_OBJECT);
                    referenceValidation.setDigest(manifestEntry.getDigest());
                    referenceValidation.setName(manifestEntry.getFileName());
                    referenceValidation.setFound(matchingDocument != null);
                    referenceValidation.setIntact(false);
                    referenceValidations.add(referenceValidation);
                }
            }
        }

        /*
         * 4) One or more ASiCEvidenceRecordManifest files may be present. They shall contain one ASiCManifest
         * element instance conformant to clause A.4 that shall reference in the SigReference element a file containing
         * an ER and the ds:DigestMethod element shall match the digest algorithm used to create the initial Archive
         * Time-stamp protecting the first ReducedHashTree element as defined in IETF RFC 4998 [8] or IETF RFC 6283 [9].
         */
        if (firstTimeStamp) {
            for (ManifestEntry manifestEntry : manifestFile.getEntries()) {
                for (ReferenceValidation reference : referenceValidations) {
                    if (manifestEntry.getFileName().equals(reference.getName()) &&
                            manifestEntry.getDigest() != null && reference.getDigest() != null &&
                            !manifestEntry.getDigest().getAlgorithm().equals(reference.getDigest().getAlgorithm())) {
                        LOG.warn("The digest algorithm '{}' defined in a manifest file with name '{}' does not match " +
                                        "the digest algorithm '{}' used within an evidence record for file with name '{}'",
                                manifestEntry.getDigest().getAlgorithm(), manifestFile.getFilename(),
                                reference.getDigest().getAlgorithm(), manifestEntry.getFileName());
                        reference.setIntact(false);
                    }
                }
            }
        }

        return referenceValidations;
    }

    /**
     * This method is used to verify archive data objects for presence document digests within {@code digestValueGroup}.
     *
     * @param digestValueGroup {@link DigestValueGroup} to find document corresponding digest in
     * @param archiveTimeStampChain {@link ArchiveTimeStampChainObject} defines configuration for validation
     * @param detachedContents a list of detached {@link DSSDocument}s
     * @param manifestFile {@link ManifestFile}, when present
     * @return a list of {@link ReferenceValidation}s
     */
    protected List<ReferenceValidation> validateArchiveDataObjects(DigestValueGroup digestValueGroup,
                                                                   ArchiveTimeStampChainObject archiveTimeStampChain,
                                                                   List<DSSDocument> detachedContents,
                                                                   ManifestFile manifestFile) {
        final List<ReferenceValidation> result = new ArrayList<>();
        final List<String> foundDocuments = new ArrayList<>();

        DigestAlgorithm digestAlgorithm = archiveTimeStampChain.getDigestAlgorithm();

        // process ER data objects at first
        List<byte[]> digestValues = digestValueGroup.getDigestValues();
        for (byte[] hashValue : digestValues) {
            ReferenceValidation referenceValidation = new ReferenceValidation();
            referenceValidation.setType(DigestMatcherType.EVIDENCE_RECORD_ARCHIVE_OBJECT);

            Digest digest = new Digest(digestAlgorithm, hashValue);
            referenceValidation.setDigest(digest);

            DSSDocument matchingDocument = getMatchingDocument(digest, archiveTimeStampChain, detachedContents);
            ManifestEntry matchingManifestEntry = getMatchingManifestEntry(manifestFile, digest, matchingDocument);

            if (manifestFile != null) {
                if (matchingManifestEntry != null) {
                    referenceValidation.setFound(matchingManifestEntry.isFound() || matchingDocument != null);
                    referenceValidation.setIntact(matchingManifestEntry.isIntact() && matchingDocument != null);
                    referenceValidation.setName(matchingManifestEntry.getFileName());
                    foundDocuments.add(matchingManifestEntry.getFileName());

                } else if (matchingDocument != null) {
                    referenceValidation.setName(matchingDocument.getName());
                    foundDocuments.add(matchingDocument.getName());

                } else {
                    referenceValidation.setType(DigestMatcherType.EVIDENCE_RECORD_ORPHAN_REFERENCE);
                    referenceValidation.setFound(false);
                    referenceValidation.setIntact(false);
                }

            } else if (matchingDocument != null) {
                referenceValidation.setFound(true);
                referenceValidation.setIntact(true);
                referenceValidation.setName(matchingDocument.getName());
                foundDocuments.add(matchingDocument.getName());

            } else if (Utils.collectionSize(digestValues) == 1 && Utils.collectionSize(detachedContents) == 1) {
                // if one document is expected and provided -> assume it as a signed data
                referenceValidation.setFound(true);
                referenceValidation.setIntact(false);
                referenceValidation.setName(detachedContents.get(0).getName());
                foundDocuments.add(detachedContents.get(0).getName());

            } else {
                referenceValidation.setType(DigestMatcherType.EVIDENCE_RECORD_ORPHAN_REFERENCE);
                referenceValidation.setFound(false);
                referenceValidation.setIntact(false);
            }

            result.add(referenceValidation);
        }
        return result;
    }

    /**
     * Returns a validated manifest entry matching the given {@code digest} or {@code document}
     *
     * @param manifestFile {@link ManifestFile}
     * @param digest {@link Digest}
     * @param document {@link DSSDocument}
     * @return {@link ManifestEntry}, if found
     */
    protected ManifestEntry getMatchingManifestEntry(ManifestFile manifestFile, Digest digest, DSSDocument document) {
        if (manifestFile != null) {
            for (ManifestEntry manifestEntry : manifestFile.getEntries()) {
                Digest manifestEntryDigest = manifestEntry.getDigest();
                if (digest.equals(manifestEntryDigest)) {
                    return manifestEntry;
                }
                if (document != null && document.getName().equals(manifestEntry.getFileName())) {
                    return manifestEntry;
                }
            }
            LOG.debug("No manifest entry found matching the archive data object with digest value '{}'", digest.getHexValue());
        }
        return null;
    }

    /**
     * This method returns a document with matching {@code Digest} from a provided list of {@code detachedContents}
     *
     * @param digest {@link Digest} to check
     * @param archiveTimeStampChain {@link ArchiveTimeStampChainObject} defines configuration for validation
     * @param detachedContents a list of {@link DSSDocument}s
     * @return {@link DSSDocument} if matching document found, NULL otherwise
     */
    protected DSSDocument getMatchingDocument(Digest digest, ArchiveTimeStampChainObject archiveTimeStampChain,
                                              List<DSSDocument> detachedContents) {
        byte[] documentDigest;
        if (Utils.isCollectionNotEmpty(detachedContents)) {
            for (DSSDocument document : detachedContents) {
                documentDigest = getDocumentDigest(document, archiveTimeStampChain);
                if (Arrays.equals(digest.getValue(), documentDigest)) {
                    return document;
                }
            }
        }
        return null;
    }

    /**
     * This method returns a matching document for the given {@code manifestEntry}
     *
     * @param manifestEntry {@link ManifestEntry} to get matching document for
     * @param detachedContents a list of {@link DSSDocument}s provided within a container
     * @return {@link DSSDocument} matching document when found, NULL otherwise
     */
    protected DSSDocument getMatchingDocument(ManifestEntry manifestEntry, List<DSSDocument> detachedContents) {
        for (DSSDocument document : detachedContents) {
            if (manifestEntry.getFileName().equals(document.getName())) {
                return document;
            }
        }
        return null;
    }

    /**
     * Computes hash on {@code archiveTimeStamp} element provided the {@code archiveTimeStampChain}'s attributes
     *
     * @param digestAlgorithm {@link DigestAlgorithm} to be used for hash computation
     * @param archiveTimeStamp {@link ArchiveTimeStampObject} to compute hash on
     * @param archiveTimeStampChain {@link ArchiveTimeStampChainObject} defines configuration for hash computation
     * @return {@link DSSMessageDigest}
     */
    protected abstract DSSMessageDigest computeTimeStampHash(DigestAlgorithm digestAlgorithm,
                                                             ArchiveTimeStampObject archiveTimeStamp, ArchiveTimeStampChainObject archiveTimeStampChain);

    /**
     * Computes hash of {@code ArchiveTimeStampSequenceElement} preceding the incorporation of {@code ArchiveTimeStampChainObject}
     *
     * @param archiveTimeStampChain {@link ArchiveTimeStampChainObject} to compute hash for
     * @param detachedContents a list of {@link DSSDocument}s provided within a container
     * @return {@link DSSMessageDigest}
     */
    protected abstract DSSMessageDigest computePrecedingTimeStampSequenceHash(
            ArchiveTimeStampChainObject archiveTimeStampChain, List<DSSDocument> detachedContents);
    
    /**
     * Computes a hash value for a group of hashes
     *
     * @param digestAlgorithm {@link DigestAlgorithm} to be used for a hash computation
     * @param digestValueGroup {@link DigestValueGroup} containing grouped elements from a hash tree
     * @param otherObjectDigests additional hash values obtained from other computations
     * @return {@link DSSMessageDigest}
     */
    protected DSSMessageDigest computeDigestValueGroupHash(DigestAlgorithm digestAlgorithm,
                                                           DigestValueGroup digestValueGroup, DSSMessageDigest... otherObjectDigests) {
        /*
         * The algorithm by which a root hash value is generated from the
         * <HashTree> element is as follows: the content of each <DigestValue>
         element within the first <Sequence> element is base64 ([RFC4648],
         * using the base64 alphabet not the base64url alphabet) decoded to
         * obtain a binary value (representing the hash value). All collected
         * hash values from the sequence are ordered in binary ascending order,
         * concatenated and a new hash value is generated from that string.
         * With one exception to this rule: when the first <Sequence> element
         * has only one <DigestValue> element, then its binary value is added to
         * the next list obtained from the next <Sequence> element.
         */
        // 1. Group together items
        List<byte[]> hashValueList = new ArrayList<>(digestValueGroup.getDigestValues());
        for (DSSMessageDigest messageDigest : otherObjectDigests) {
            if (!messageDigest.isEmpty()) {
                hashValueList.add(messageDigest.getValue());
            }
        }
        // 2a. Exception
        if (Utils.collectionSize(hashValueList) == 1) {
            return new DSSMessageDigest(digestAlgorithm, hashValueList.get(0));
        }
        // 2b. Binary ascending sort
        hashValueList.sort(ByteArrayComparator.getInstance());
        // 3. Concatenate
        final DSSMessageDigestCalculator digestCalculator = new DSSMessageDigestCalculator(digestAlgorithm);
        for (byte[] hashValue : hashValueList) {
            digestCalculator.update(hashValue);
        }
        // 4. Calculate hash value
        return digestCalculator.getMessageDigest();
    }

}
