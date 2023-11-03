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

            List<? extends ArchiveTimeStampObject> archiveTimeStamps = archiveTimeStampChain.getArchiveTimeStamps();
            Iterator<? extends ArchiveTimeStampObject> archiveTimeStampsIt = archiveTimeStamps.iterator();
            while (archiveTimeStampsIt.hasNext()) {
                ArchiveTimeStampObject archiveTimeStamp = archiveTimeStampsIt.next();

                List<ReferenceValidation> timestampValidations = new ArrayList<>();
                DSSMessageDigest lastMessageDigest = DSSMessageDigest.createEmptyDigest();
                List<? extends DigestValueGroup> hashTree = archiveTimeStamp.getHashTree();
                for (DigestValueGroup digestValueGroup : hashTree) {
                    // Validation of first HashTree/Sequence
                    if (lastMessageDigest.isEmpty()) {
                        List<DSSDocument> detachedContents = lastTimeStampHash.isEmpty() ?
                                evidenceRecord.getDetachedContents() : Collections.emptyList();
                        // execute for all time-stamps in order to create reference validations
                        List<ReferenceValidation> archiveDataObjectValidations =
                                validateArchiveDataObjects(digestValueGroup, archiveTimeStampChain, detachedContents);

                        // if first time-stamp in a next ArchiveTimeStampChain
                        if (lastTimeStampHash.isEmpty()) {
                            if (!firstArchiveTimeStampChain) {
                                DSSMessageDigest lastTimeStampSequenceHash = computePrecedingTimeStampSequenceHash(digestAlgorithm, archiveTimeStampChain);
                                // validate first time-stamp in ArchiveTimeStampChain
                                timestampValidations = validateArchiveTimeStampSequenceDigest(archiveDataObjectValidations, lastTimeStampSequenceHash);

                            } else {
                                referenceValidations.addAll(archiveDataObjectValidations);
                            }

                        } else {
                            // validate other time-stamps
                            timestampValidations = validateArchiveTimeStampDigest(archiveDataObjectValidations, lastTimeStampHash);
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

    private List<ReferenceValidation> validateArchiveTimeStampSequenceDigest(List<ReferenceValidation> referenceValidations, DSSMessageDigest lastTimeStampSequenceHash) {
        return validateAdditionalDigest(referenceValidations, lastTimeStampSequenceHash, DigestMatcherType.EVIDENCE_RECORD_ARCHIVE_TIME_STAMP_SEQUENCE);
    }

    private List<ReferenceValidation> validateArchiveTimeStampDigest(List<ReferenceValidation> referenceValidations, DSSMessageDigest lastTimeStampHash) {
        return validateAdditionalDigest(referenceValidations, lastTimeStampHash, DigestMatcherType.EVIDENCE_RECORD_ARCHIVE_TIME_STAMP);
    }

    private List<ReferenceValidation> validateAdditionalDigest(List<ReferenceValidation> referenceValidations, DSSMessageDigest messageDigest, DigestMatcherType type) {
        List<ReferenceValidation> invalidReferences = referenceValidations.stream().filter(r -> !r.isFound()).collect(Collectors.toList());
        for (ReferenceValidation reference : invalidReferences) {
            if (reference.getDigest() != null && Arrays.equals(messageDigest.getValue(), reference.getDigest().getValue())) {
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

    /**
     * This method is used to verify archive data objects for presence document digests within {@code digestValueGroup}.
     *
     * @param digestValueGroup {@link DigestValueGroup} to find document corresponding digest in
     * @param archiveTimeStampChain {@link ArchiveTimeStampChainObject} defines configuration for validation
     * @return a list of {@link ReferenceValidation}s
     */
    protected List<ReferenceValidation> validateArchiveDataObjects(DigestValueGroup digestValueGroup,
                                                                   ArchiveTimeStampChainObject archiveTimeStampChain,
                                                                   List<DSSDocument> detachedContents) {
        final List<ReferenceValidation> result = new ArrayList<>();
        final List<String> foundDocuments = new ArrayList<>();

        DigestAlgorithm digestAlgorithm = archiveTimeStampChain.getDigestAlgorithm();
        ManifestFile manifestFile = evidenceRecord.getManifestFile();

        // process ER data objects at first
        List<byte[]> digestValues = digestValueGroup.getDigestValues();
        for (byte[] hashValue : digestValues) {
            ReferenceValidation referenceValidation = new ReferenceValidation();
            referenceValidation.setType(DigestMatcherType.EVIDENCE_RECORD_ARCHIVE_OBJECT);

            Digest digest = new Digest(digestAlgorithm, hashValue);
            referenceValidation.setDigest(digest);

            DSSDocument matchingDocument = getMatchingDocument(digest, archiveTimeStampChain, detachedContents);
            ManifestEntry matchingManifestEntry = getMatchingManifestEntry(digest, matchingDocument);

            if (manifestFile != null) {
                if (matchingManifestEntry != null) {
                    referenceValidation.setFound(matchingManifestEntry.isFound() || matchingDocument != null);
                    referenceValidation.setIntact(matchingManifestEntry.isIntact() && matchingDocument != null);
                    referenceValidation.setDigest(matchingManifestEntry.getDigest());
                    referenceValidation.setName(matchingManifestEntry.getFileName());
                    foundDocuments.add(matchingManifestEntry.getFileName());

                } else if (matchingDocument != null) {
                    referenceValidation.setName(matchingDocument.getName());
                    foundDocuments.add(matchingDocument.getName());
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

        // create empty ReferenceValidations for not found manifest entries, when applicable
        if (manifestFile != null && Utils.collectionSize(manifestFile.getEntries()) > Utils.collectionSize(foundDocuments)) {
            List<ReferenceValidation> failedReferences = result.stream().filter(r -> r.getName() == null).collect(Collectors.toList());
            if (Utils.collectionSize(manifestFile.getEntries()) - Utils.collectionSize(foundDocuments) >= Utils.collectionSize(failedReferences)) {
                // remove failed references
                for (ReferenceValidation reference : failedReferences) {
                    result.remove(reference);
                }
            }
            // add references from a manifest
            for (ManifestEntry manifestEntry : manifestFile.getEntries()) {
                if (!foundDocuments.contains(manifestEntry.getFileName())) {
                    LOG.warn("Manifest entry with name '{}' was not found within evidence record data objects!", manifestEntry.getFileName());

                    DSSDocument matchingDocument = getMatchingDocument(manifestEntry, detachedContents);

                    ReferenceValidation referenceValidation = new ReferenceValidation();
                    referenceValidation.setType(DigestMatcherType.EVIDENCE_RECORD_ARCHIVE_OBJECT);
                    referenceValidation.setDigest(manifestEntry.getDigest());
                    referenceValidation.setName(manifestEntry.getFileName());
                    referenceValidation.setFound(matchingDocument != null);
                    referenceValidation.setIntact(false);
                    result.add(referenceValidation);
                }
            }
        }

        return result;
    }

    /**
     * Returns a validated manifest entry matching the given {@code digest} or {@code document}
     *
     * @param digest {@link Digest}
     * @param document {@link DSSDocument}
     * @return {@link ManifestEntry}, if found
     */
    protected ManifestEntry getMatchingManifestEntry(Digest digest, DSSDocument document) {
        ManifestFile manifestFile = evidenceRecord.getManifestFile();
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
            LOG.warn("No manifest entry found matching the archive data object with digest value '{}'", digest.getHexValue());
        }
        return null;
    }

    /**
     * This method returns a document with matching {@code Digest} from a provided list of {@code detachedContents}
     *
     * @param digest {@link Digest} to check
     * @param archiveTimeStampChain {@link ArchiveTimeStampChainObject} defines configuration for validation
     * @return {@link DSSDocument} if matching document found, NULL otherwise
     */
    protected DSSDocument getMatchingDocument(Digest digest, ArchiveTimeStampChainObject archiveTimeStampChain,
                                              List<DSSDocument> detachedContents) {
        byte[] documentDigest;
        if (Utils.isCollectionNotEmpty(detachedContents)) {
            for (DSSDocument document : detachedContents) {
                String base64Digest = document.getDigest(digest.getAlgorithm());
                documentDigest = Utils.fromBase64(base64Digest);
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
     * @param digestAlgorithm {@link DigestAlgorithm} to be used for hash computation
     * @param archiveTimeStampChain {@link ArchiveTimeStampChainObject} to compute hash for
     * @return {@link DSSMessageDigest}
     */
    protected abstract DSSMessageDigest computePrecedingTimeStampSequenceHash(DigestAlgorithm digestAlgorithm, ArchiveTimeStampChainObject archiveTimeStampChain);

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
