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
package eu.europa.esig.dss.evidencerecord.asn1.validation;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.enumerations.EvidenceRecordIncorporationType;
import eu.europa.esig.dss.evidencerecord.asn1.digest.ASN1ArchiveTimeStampSequenceDigestHelper;
import eu.europa.esig.dss.evidencerecord.asn1.digest.ASN1EvidenceRecordDataObjectDigestBuilder;
import eu.europa.esig.dss.evidencerecord.common.validation.ArchiveTimeStampChainObject;
import eu.europa.esig.dss.evidencerecord.common.validation.ArchiveTimeStampObject;
import eu.europa.esig.dss.evidencerecord.common.validation.EvidenceRecordTimeStampSequenceVerifier;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSMessageDigest;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.ReferenceValidation;
import eu.europa.esig.dss.spi.validation.evidencerecord.EmbeddedEvidenceRecordHelper;
import eu.europa.esig.dss.spi.x509.evidencerecord.digest.DataObjectDigestBuilder;
import eu.europa.esig.dss.utils.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Verifies ArchiveTimeStampSequence for an ASN.1 Evidence Record
 *
 */
public class ASN1EvidenceRecordTimeStampSequenceVerifier extends EvidenceRecordTimeStampSequenceVerifier {

	private static final Logger LOG = LoggerFactory.getLogger(ASN1EvidenceRecordTimeStampSequenceVerifier.class);

    /**
     * Default constructor to instantiate an ASN.1 evidence record verifier
     *
     * @param evidenceRecord {@link ASN1EvidenceRecord} XML evidence record to be validated
     */
    public ASN1EvidenceRecordTimeStampSequenceVerifier(ASN1EvidenceRecord evidenceRecord) {
        super(evidenceRecord);
    }

    @Override
    protected DataObjectDigestBuilder getDataObjectDigestBuilder(DSSDocument document, ArchiveTimeStampChainObject archiveTimeStampChain) {
        DigestAlgorithm digestAlgorithm = archiveTimeStampChain.getDigestAlgorithm();
        return new ASN1EvidenceRecordDataObjectDigestBuilder(document, digestAlgorithm);
    }

    /**
     * This method returns a document with matching {@code Digest} from a provided list of {@code detachedContents}
     *
     * @param digest {@link Digest} to check
     * @param archiveTimeStampChain {@link ArchiveTimeStampChainObject} defines configuration for validation
     * @param lastTimeStampSequenceHash {@link DSSMessageDigest} hash of the last archive time-stamp sequence
     * @return {@link DSSDocument} if matching document found, NULL otherwise
     */
    @Override
    protected DSSDocument getMatchingDocument(Digest digest, ArchiveTimeStampChainObject archiveTimeStampChain,
                                              DSSMessageDigest lastTimeStampSequenceHash, List<DSSDocument> detachedContents) {
        if (lastTimeStampSequenceHash.isEmpty()) {
            return super.getMatchingDocument(digest, archiveTimeStampChain, lastTimeStampSequenceHash, detachedContents);

        } else if (Utils.isCollectionNotEmpty(detachedContents)) {
            for (DSSDocument document : detachedContents) {
                DSSMessageDigest chainAndDocumentHash = getEvidenceRecordRenewalDigestBuilderHelper()
                        .computeChainAndDocumentHash(lastTimeStampSequenceHash, document);
                byte[] documentDigest = chainAndDocumentHash.getValue();
                if (Arrays.equals(digest.getValue(), documentDigest)) {
                    return document;
                }
            }
        }
        return null;
    }
    
    @Override
    protected boolean checkHashTreeValidity(ArchiveTimeStampObject archiveTimeStamp, ArchiveTimeStampChainObject archiveTimeStampChain) {
        ASN1ArchiveTimeStampObject asn1ArchiveTimeStampObject = (ASN1ArchiveTimeStampObject) archiveTimeStamp;
        if (asn1ArchiveTimeStampObject.getDigestAlgorithm() != archiveTimeStampChain.getDigestAlgorithm()) {
            LOG.warn("The DigestAlgorithm '{}' found in ArchiveTimeStamp does not correspond to the DigestAlgorithm " +
                            "within the old Archive Timestamp '{}'! Unable to ensure validity of referenced content.",
                    asn1ArchiveTimeStampObject.getDigestAlgorithm().getName(), archiveTimeStampChain.getDigestAlgorithm().getName());
            return false;
        }
        return true;
    }

    @Override
    protected DSSMessageDigest computeTimeStampHash(ArchiveTimeStampObject archiveTimeStamp) {
        return getEvidenceRecordRenewalDigestBuilderHelper().buildTimeStampRenewalDigest(archiveTimeStamp);
    }

    @Override
    protected DSSMessageDigest computeTimeStampSequenceHash(ArchiveTimeStampChainObject archiveTimeStampChain) {
        return getEvidenceRecordRenewalDigestBuilderHelper().buildArchiveTimeStampSequenceDigest(archiveTimeStampChain);
    }

    @Override
    protected List<ReferenceValidation> validateArchiveTimeStampSequenceDigest(List<ReferenceValidation> referenceValidations,
                                                                               DSSMessageDigest lastTimeStampSequenceHashes) {
        // ASN.1 use a concatenation (archiveTimeStampSequenceHash || documentHash). No additional entry is required.
        return referenceValidations;
    }

    @Override
    protected List<ReferenceValidation> validateMasterSignatureDigest(List<ReferenceValidation> referenceValidations,
            DigestAlgorithm digestAlgorithm, DSSMessageDigest lastTimeStampSequenceHash) {
        EmbeddedEvidenceRecordHelper embeddedEvidenceRecordHelper = evidenceRecord.getEmbeddedEvidenceRecordHelper();
        Digest masterSignatureDigest = embeddedEvidenceRecordHelper.getMasterSignatureDigest(digestAlgorithm);
        referenceValidations = validateDigestForLastTimeStampSequence(referenceValidations, masterSignatureDigest,
                lastTimeStampSequenceHash, DigestMatcherType.EVIDENCE_RECORD_MASTER_SIGNATURE);

        if (!isMasterSignatureDigestFound(referenceValidations)) {
            if (embeddedEvidenceRecordHelper.isEncodingSelectionSupported()) {
                // The second approach is implemented in order to support ETSI TS 119 122-3 v1.1.1 hash generation
                LOG.debug("Unable to match digest of a master signature for the evidence record by computing " +
                        "the hash using existing coding, try to compute the hash using DER coding...");
                masterSignatureDigest = embeddedEvidenceRecordHelper.getMasterSignatureDigest(digestAlgorithm, true);
                referenceValidations = validateDigestForLastTimeStampSequence(referenceValidations, masterSignatureDigest,
                        lastTimeStampSequenceHash, DigestMatcherType.EVIDENCE_RECORD_MASTER_SIGNATURE);
            }
        }
        if (EvidenceRecordIncorporationType.EXTERNAL_EVIDENCE_RECORD == evidenceRecord.getIncorporationType()) {
            Digest detachedDocumentDigest = getDetachedDocumentDigestForExternalEvidenceRecord(digestAlgorithm);
            referenceValidations = validateDigestForLastTimeStampSequence(referenceValidations, detachedDocumentDigest,
                    lastTimeStampSequenceHash, DigestMatcherType.EVIDENCE_RECORD_ARCHIVE_OBJECT);
        }
        return referenceValidations;
    }

    private List<ReferenceValidation> validateDigestForLastTimeStampSequence(List<ReferenceValidation> referenceValidations, Digest digestToValidate,
                                                                             DSSMessageDigest lastTimeStampSequenceHash, DigestMatcherType digestMatcherType) {
        if (!lastTimeStampSequenceHash.isEmpty()) {
            digestToValidate = getEvidenceRecordRenewalDigestBuilderHelper().
                    computeChainAndDocumentHash(lastTimeStampSequenceHash, digestToValidate);
        }
        return validateAdditionalDigest(referenceValidations, digestToValidate, digestMatcherType);
    }

    private boolean isMasterSignatureDigestFound(List<ReferenceValidation> referenceValidations) {
        return referenceValidations.stream().anyMatch(r -> DigestMatcherType.EVIDENCE_RECORD_MASTER_SIGNATURE == r.getType() && r.isIntact());
    }

    private Digest getDetachedDocumentDigestForExternalEvidenceRecord(DigestAlgorithm digestAlgorithm) {
        if (detachedContentPresentForExternalEvidenceRecord()) {
            return evidenceRecord.getDetachedContents().get(0).getDigest(digestAlgorithm);
        } else {
            LOG.warn("One and only one detached document was expected on validation of an 'external-evidence-records'. " +
                    "Provided documents: '{}'", Utils.collectionSize(evidenceRecord.getDetachedContents()));
            return new Digest();
        }
    }

    private boolean detachedContentPresentForExternalEvidenceRecord() {
        return Utils.collectionSize(evidenceRecord.getDetachedContents()) == 1;
    }

    @Override
    protected List<byte[]> getLastTimeStampSequenceHashList(
            DSSMessageDigest lastTimeStampSequenceHash, List<DSSDocument> detachedDocuments) {
        if (Utils.isCollectionEmpty(detachedDocuments)) {
            return super.getLastTimeStampSequenceHashList(lastTimeStampSequenceHash, detachedDocuments);
        }
        final List<byte[]> hashes = new ArrayList<>();
        for (DSSDocument document : detachedDocuments) {
            DSSMessageDigest documentMessageDigest = getEvidenceRecordRenewalDigestBuilderHelper().
                    computeChainAndDocumentHash(lastTimeStampSequenceHash, document);
            hashes.add(documentMessageDigest.getValue());
        }
        return hashes;
    }

    /**
     * This method returns a helper class containing supporting methods for digest computation in relation
     * to an archive-time-stamp-sequence
     *
     * @return {@link ASN1ArchiveTimeStampSequenceDigestHelper}
     */
    protected ASN1ArchiveTimeStampSequenceDigestHelper getEvidenceRecordRenewalDigestBuilderHelper() {
        return new ASN1ArchiveTimeStampSequenceDigestHelper((ASN1EvidenceRecord) evidenceRecord);
    }

}
