package eu.europa.esig.dss.evidencerecord.asn1.validation;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.evidencerecord.common.validation.ArchiveTimeStampChainObject;
import eu.europa.esig.dss.evidencerecord.common.validation.ArchiveTimeStampObject;
import eu.europa.esig.dss.evidencerecord.common.validation.EvidenceRecordTimeStampSequenceVerifier;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSMessageDigest;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.ReferenceValidation;
import eu.europa.esig.dss.spi.DSSMessageDigestCalculator;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import org.bouncycastle.asn1.tsp.ArchiveTimeStampChain;
import org.bouncycastle.asn1.tsp.ArchiveTimeStampSequence;
import org.bouncycastle.asn1.tsp.EvidenceRecord;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
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

    /**
     * This method returns a document with matching {@code Digest} from a provided list of {@code detachedContents}
     *
     * @param digest {@link Digest} to check
     * @param archiveTimeStampChain {@link ArchiveTimeStampChainObject} defines configuration for validation
     * @return {@link DSSDocument} if matching document found, NULL otherwise
     */
    @Override
    protected DSSDocument getMatchingDocument(Digest digest, ArchiveTimeStampChainObject archiveTimeStampChain,
                                              List<DSSDocument> detachedContents) {
        DSSMessageDigest archiveTimeStampSequenceDigest = null;
        if (archiveTimeStampChain.getOrder() > 1) {
            archiveTimeStampSequenceDigest = computePrecedingTimeStampSequenceHash(archiveTimeStampChain, detachedContents);
        }
        if (Utils.isCollectionNotEmpty(detachedContents)) {
            for (DSSDocument document : detachedContents) {
            	byte[] documentDigest;
               
            	if (archiveTimeStampSequenceDigest == null) {
                    String base64Digest = document.getDigest(digest.getAlgorithm());
                    documentDigest = Utils.fromBase64(base64Digest);

            	} else {
                    DSSMessageDigest chainAndDocumentHash = computeChainAndDocumentHash(archiveTimeStampSequenceDigest, document);
            		documentDigest = chainAndDocumentHash.getValue();
            	}
            	
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
    protected DSSMessageDigest computeTimeStampHash(DigestAlgorithm digestAlgorithm,
    		ArchiveTimeStampObject archiveTimeStamp, ArchiveTimeStampChainObject archiveTimeStampChain) {
        ASN1ArchiveTimeStampObject asn1ArchiveTimeStampObject = (ASN1ArchiveTimeStampObject) archiveTimeStamp;
        byte[] digestValue = DSSUtils.digest(digestAlgorithm, asn1ArchiveTimeStampObject.getTimestampToken().getEncoded());
        return new DSSMessageDigest(digestAlgorithm, digestValue);
    }
    
    @Override
    protected DSSMessageDigest computePrecedingTimeStampSequenceHash(
            ArchiveTimeStampChainObject archiveTimeStampChain, List<DSSDocument> detachedContents) {
        DigestAlgorithm digestAlgorithm = archiveTimeStampChain.getDigestAlgorithm();
        ASN1ArchiveTimeStampChainObject asn1ArchiveTimeStampChainObject = (ASN1ArchiveTimeStampChainObject) archiveTimeStampChain;

        ArchiveTimeStampSequence archiveTimeStampSequence = getArchiveTimeStampSequence();
        ArchiveTimeStampChain[] childNodes = archiveTimeStampSequence.getArchiveTimeStampChains();
        ArchiveTimeStampChain[] precedingChildNodes = new ArchiveTimeStampChain[asn1ArchiveTimeStampChainObject.getOrder() - 1];
        for (int i = 0; i < childNodes.length; i++) {
            if (i < asn1ArchiveTimeStampChainObject.getOrder() - 1) {
            	precedingChildNodes[i] = childNodes[i];
            }
        }

        // calc the preceding ATSSeq hash
        ArchiveTimeStampSequence precedingArchiveTimeStampSequence = new ArchiveTimeStampSequence(precedingChildNodes);
        DSSMessageDigest archiveTimeStampSequenceDigest;
		try {
            archiveTimeStampSequenceDigest = new DSSMessageDigest(digestAlgorithm,
                    DSSUtils.digest(digestAlgorithm, precedingArchiveTimeStampSequence.toASN1Primitive().getEncoded()));
		} catch (IOException e) {
			LOG.warn("Unable to generate ASN1 TimeStampSequence. Reason : {}", e.getMessage(), e);
			return null;
		}

        return archiveTimeStampSequenceDigest;
    }

    private ArchiveTimeStampSequence getArchiveTimeStampSequence() {
    	ASN1EvidenceRecord asn1EvidenceRecord = (ASN1EvidenceRecord) evidenceRecord;
    	EvidenceRecord evidenceRecord = asn1EvidenceRecord.getEvidenceRecord();
        return evidenceRecord.getArchiveTimeStampSequence();
    }

    @Override
    protected List<ReferenceValidation> validateArchiveTimeStampSequenceDigest(List<ReferenceValidation> referenceValidations,
                                                                               DSSMessageDigest lastTimeStampSequenceHashes) {
        // ASN.1 use a concatenation (archiveTimeStampSequenceHash || documentHash). No additional entry is required.
        return referenceValidations;
    }

    /**
     * Computes a hash value for chain-hash and document-hash
     *
     * @param archiveTimeStampChainHash {@link DSSDocument} hash of the previous ArchiveTimeStampChain
     * @param document {@link DSSDocument} detached document
     * @return {@link DSSMessageDigest}
     */
    protected DSSMessageDigest computeChainAndDocumentHash(DSSMessageDigest archiveTimeStampChainHash,
                                                           DSSDocument document) {
        DigestAlgorithm digestAlgorithm = archiveTimeStampChainHash.getAlgorithm();

        /*
         * The algorithm by which a root hash value is generated from the
         * <HashTree> element is as follows: the content of each <DigestValue>
         * element within the first <Sequence> element is base64 ([RFC4648],
         * using the base64 alphabet not the base64url alphabet) decoded to
         * obtain a binary value (representing the hash value). All collected
         * hash values from the sequence are [ordered in binary ascending order],
         * concatenated and a new hash value is generated from that string.
         * With one exception to this rule: when the first <Sequence> element
         * has only one <DigestValue> element, then its binary value is added to
         * the next list obtained from the next <Sequence> element.
         */

        // 0. Compute hash of the document
        byte[] documentMessageDigest = Utils.fromBase64(document.getDigest(digestAlgorithm));

        // 1. Group together items
        List<byte[]> hashValueList = new ArrayList<>();
        hashValueList.add(documentMessageDigest);
        hashValueList.add(archiveTimeStampChainHash.getValue());

        // 2a. Exception
        if (Utils.collectionSize(hashValueList) == 1) {
            return new DSSMessageDigest(digestAlgorithm, hashValueList.get(0));
        }

        /*
         * All known ASN.1 ERs are not sorted for this hash!
         *
         * There is an error in Figure 4 of RFC4998, which states
         * "h1' = H( binary sorted and concatenated (H(d1), ha(1)))",
         * but 5.2. point 4. clearly states "Concatenate each h(i)
         * with ha(i) and generate hash values h(i)' = H (h(i)+ ha(i)).".
         * N.b.: There is no need to sort hashes when their order is defined.
         *
         * Read more here: <a href="https://github.com/de-bund-bsi-tr-esor/ERVerifyTool/issues/2">https://github.com/de-bund-bsi-tr-esor/ERVerifyTool/issues/2</a>
         */
        // 2b. Binary ascending sort
        // hashValueList.sort(ByteArrayComparator.getInstance());

        // 3. Concatenate
        final DSSMessageDigestCalculator digestCalculator = new DSSMessageDigestCalculator(digestAlgorithm);
        for (byte[] hashValue : hashValueList) {
            digestCalculator.update(hashValue);
        }
        // 4. Calculate hash value
        return digestCalculator.getMessageDigest();
    }

    @Override
    protected List<byte[]> getLastTimeStampSequenceHashList(
            DSSMessageDigest lastTimeStampSequenceHash, List<DSSDocument> detachedDocuments) {
        if (Utils.isCollectionEmpty(detachedDocuments)) {
            return super.getLastTimeStampSequenceHashList(lastTimeStampSequenceHash, detachedDocuments);
        }
        final List<byte[]> hashes = new ArrayList<>();
        for (DSSDocument document : detachedDocuments) {
            DSSMessageDigest documentMessageDigest = computeChainAndDocumentHash(lastTimeStampSequenceHash, document);
            hashes.add(documentMessageDigest.getValue());
        }
        return hashes;
    }

}
