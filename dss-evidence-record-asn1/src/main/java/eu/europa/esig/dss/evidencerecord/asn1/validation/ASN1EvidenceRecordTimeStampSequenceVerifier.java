package eu.europa.esig.dss.evidencerecord.asn1.validation;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.evidencerecord.common.validation.ArchiveTimeStampChainObject;
import eu.europa.esig.dss.evidencerecord.common.validation.ArchiveTimeStampObject;
import eu.europa.esig.dss.evidencerecord.common.validation.ByteArrayComparator;
import eu.europa.esig.dss.evidencerecord.common.validation.DigestValueGroup;
import eu.europa.esig.dss.evidencerecord.common.validation.EvidenceRecordTimeStampSequenceVerifier;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSMessageDigest;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.DigestDocument;
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
        if (Utils.isCollectionNotEmpty(detachedContents)) {
            for (DSSDocument document : detachedContents) {
            	byte[] documentDigest;
               
            	if (archiveTimeStampChain.getOrder() <= 1)
            	{
	                if (!(document instanceof DigestDocument)) {
	                    documentDigest = DSSUtils.digest(digest.getAlgorithm(), document.openStream());
	                } else {
	                    String base64Digest = document.getDigest(digest.getAlgorithm());
	                    documentDigest = Utils.fromBase64(base64Digest);
	                }
            	}
            	else
            	{
            		DSSMessageDigest documentChainDigest = computePrecedingTimeStampSequenceHash(digest.getAlgorithm(), archiveTimeStampChain,detachedContents);
            		documentDigest = documentChainDigest.getValue();
            	}
            	
                if (Arrays.equals(digest.getValue(), documentDigest)) {
                    return document;
                }
            }
        }
        return null;
    }
    
    @Override
    protected DSSMessageDigest computeTimeStampHash(DigestAlgorithm digestAlgorithm,
    		ArchiveTimeStampObject archiveTimeStamp, ArchiveTimeStampChainObject archiveTimeStampChain) {
        ASN1ArchiveTimeStampObject asn1ArchiveTimeStampObject = (ASN1ArchiveTimeStampObject) archiveTimeStamp;
        byte[] digestValue = DSSUtils.digest(digestAlgorithm, asn1ArchiveTimeStampObject.getTimestampToken().getEncoded());
        return new DSSMessageDigest(digestAlgorithm, digestValue);
    }

    @Override
    protected DSSMessageDigest computePrecedingTimeStampSequenceHash(DigestAlgorithm digestAlgorithm,
            ArchiveTimeStampChainObject archiveTimeStampChain, List<DSSDocument> detachedContents) {
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
        byte[] digestValue;
		try {
			digestValue = DSSUtils.digest(digestAlgorithm, precedingArchiveTimeStampSequence.toASN1Primitive().getEncoded());
		} catch (IOException e) {
			LOG.warn("Unable to generate ASN1 TimeStampSequence. Reason : {}", e.getMessage(), e);
			return null;
		}

		// get hash from document(s)
		List<byte[]> digestValues = new ArrayList<>();
		for (DSSDocument document : detachedContents) {
			digestValues.add(Utils.fromBase64(document.getDigest(digestAlgorithm)));
		}
		DigestValueGroup digestValueGroup = new DigestValueGroup();
		digestValueGroup.setDigestValues(digestValues);
		DSSMessageDigest documentHash = computeDigestValueGroupHash(digestAlgorithm, digestValueGroup);

		// sort both hashes in ascending order, concat hashes and create a new digest
        return computeChainAndDocumentHash(digestAlgorithm, documentHash, new DSSMessageDigest(digestAlgorithm, digestValue), false);
    }

    private ArchiveTimeStampSequence getArchiveTimeStampSequence() {
    	ASN1EvidenceRecord asn1EvidenceRecord = (ASN1EvidenceRecord) evidenceRecord;
    	EvidenceRecord evidenceRecord = asn1EvidenceRecord.getEvidenceRecord();
        return evidenceRecord.getArchiveTimeStampSequence();
    }

    /**
     * Computes a hash value for chain-hash and document-hash
     * Note: rfc4998 is ambiguous in this case
     * All known ASN.1 ERs are not sorted for this hash!
     * Read more here: <a href="https://github.com/de-bund-bsi-tr-esor/ERVerifyTool/issues/2">https://github.com/de-bund-bsi-tr-esor/ERVerifyTool/issues/2</a>
     *
     * @param digestAlgorithm {@link DigestAlgorithm} to be used for a hash computation
     * @param documentHash {@link DSSMessageDigest} the hash of the document
     * @param sort whether the hash value should be sorted
     * @return {@link DSSMessageDigest}
     */
    protected DSSMessageDigest computeChainAndDocumentHash(
            DigestAlgorithm digestAlgorithm, DSSMessageDigest documentHash, DSSMessageDigest chainHash, boolean sort) {
        /*
         * The algorithm by which a root hash value is generated from the
         * <HashTree> element is as follows: the content of each <DigestValue>
         element within the first <Sequence> element is base64 ([RFC4648],
         * using the base64 alphabet not the base64url alphabet) decoded to
         * obtain a binary value (representing the hash value). All collected
         * hash values from the sequence are [ordered in binary ascending order],
         * concatenated and a new hash value is generated from that string.
         * With one exception to this rule: when the first <Sequence> element
         * has only one <DigestValue> element, then its binary value is added to
         * the next list obtained from the next <Sequence> element.
         */
        // 1. Group together items
        List<byte[]> hashValueList = new ArrayList<>();
        hashValueList.add(documentHash.getValue());
        hashValueList.add(chainHash.getValue());

        // 2a. Exception
        if (Utils.collectionSize(hashValueList) == 1) {
            return new DSSMessageDigest(digestAlgorithm, hashValueList.get(0));
        }

        // 2b. Binary ascending sort
        // NOTE: See comment above
        // TODO : what about accepting both options (i.e. sorted/not sorted) ?
        if (sort) {
        	hashValueList.sort(ByteArrayComparator.getInstance());
        }

        // 3. Concatenate
        final DSSMessageDigestCalculator digestCalculator = new DSSMessageDigestCalculator(digestAlgorithm);
        for (byte[] hashValue : hashValueList) {
            digestCalculator.update(hashValue);
        }
        // 4. Calculate hash value
        return digestCalculator.getMessageDigest();
    }

}
