package eu.europa.esig.dss.evidencerecord.asn1.validation;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.evidencerecord.common.validation.ArchiveTimeStampObject;
import eu.europa.esig.dss.evidencerecord.common.validation.EvidenceRecordParser;
import eu.europa.esig.dss.exception.IllegalInputException;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.tsp.ArchiveTimeStamp;
import org.bouncycastle.asn1.tsp.ArchiveTimeStampChain;
import org.bouncycastle.asn1.tsp.ArchiveTimeStampSequence;
import org.bouncycastle.asn1.tsp.EvidenceRecord;
import org.bouncycastle.asn1.tsp.PartialHashtree;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * This class is used to parse an ASN.1 Evidence Record
 *
 */
public class ASN1EvidenceRecordParser implements EvidenceRecordParser {
	
	private static final Logger LOG = LoggerFactory.getLogger(ASN1EvidenceRecordParser.class);

    /** The BouncyCastle evidence record object to be parsed */
    private final EvidenceRecord evidenceRecord;

    /**
     * Default constructor
     *
     * @param evidenceRecord {@link EvidenceRecord}
     */
    public ASN1EvidenceRecordParser(final EvidenceRecord evidenceRecord) {
        this.evidenceRecord = evidenceRecord;
    }

    /**
     * Parses the XML Evidence Record object and returns a list of {@code ArchiveTimeStampChainObject}s
     * representing an archive time-stamp sequence
     *
     * @return a list of {@code ArchiveTimeStampChainObject}s
     */
    @Override
    public List<ASN1ArchiveTimeStampChainObject> parse() {
    	ArchiveTimeStampSequence archiveTimeStampSequenceList = this.evidenceRecord.getArchiveTimeStampSequence();
        if (archiveTimeStampSequenceList != null && archiveTimeStampSequenceList.size() > 0) {
        	ASN1ArchiveTimeStampChainObject[] result = new ASN1ArchiveTimeStampChainObject[archiveTimeStampSequenceList.size()];
            for (int i = 0; i < archiveTimeStampSequenceList.size(); i++) {
                final ArchiveTimeStampChain archiveTimeStampChain = archiveTimeStampSequenceList.getArchiveTimeStampChains()[i];
                ASN1ArchiveTimeStampChainObject archiveTimeStampChainObject = getASN1ArchiveTimeStampChainObject(archiveTimeStampChain, i+1);
                result[i] = archiveTimeStampChainObject;
            }
            return Arrays.asList(result);
        }

        return Collections.emptyList();
    }
    
    private ASN1ArchiveTimeStampChainObject getASN1ArchiveTimeStampChainObject(ArchiveTimeStampChain archiveTimeStampChain, int order) {
    	ASN1ArchiveTimeStampChainObject archiveTimeStampChainObject = new ASN1ArchiveTimeStampChainObject(archiveTimeStampChain);
        archiveTimeStampChainObject.setDigestAlgorithm(getDigestAlgorithm(archiveTimeStampChain));
        archiveTimeStampChainObject.setOrder(order);
        archiveTimeStampChainObject.setArchiveTimeStamps(getASN1ArchiveTimeStamps(archiveTimeStampChain));
        return archiveTimeStampChainObject;
    }
    
    private DigestAlgorithm getDigestAlgorithm(ArchiveTimeStampChain archiveTimeStampChain) {
    	// TODO: ANS.1 allow digest algo definition within each ArchiveTimeStamp, while it should be the same as the one in the chain, we may want to add additional verification step
        // return the first value for now
    	AlgorithmIdentifier algIdentifier = archiveTimeStampChain.getArchiveTimestamps()[0].getDigestAlgorithmIdentifier();
        return DigestAlgorithm.forOID(algIdentifier.getAlgorithm().getId());
    }

    private List<? extends ArchiveTimeStampObject> getASN1ArchiveTimeStamps(ArchiveTimeStampChain archiveTimeStampChain) {
        final ArchiveTimeStamp[] archiveTimeStampList = archiveTimeStampChain.getArchiveTimestamps();
        if (archiveTimeStampList != null && archiveTimeStampList.length > 0) {
        	ASN1ArchiveTimeStampObject[] result = new ASN1ArchiveTimeStampObject[archiveTimeStampList.length];
            for (int i = 0; i < archiveTimeStampList.length; i++) {
                final ArchiveTimeStamp archiveTimeStamp = archiveTimeStampList[i];
                ASN1ArchiveTimeStampObject archiveTimeStampObject = getASN1ArchiveTimeStampObject(archiveTimeStamp, i+1);
                result[i] = archiveTimeStampObject;
            }
            return Arrays.asList(result);
        }
        return Collections.emptyList();
    }
    
    private ASN1ArchiveTimeStampObject getASN1ArchiveTimeStampObject(ArchiveTimeStamp archiveTimeStamp, int order) {
    	ASN1ArchiveTimeStampObject archiveTimeStampObject = new ASN1ArchiveTimeStampObject(archiveTimeStamp);
        archiveTimeStampObject.setHashTree(getHashTree(archiveTimeStamp));
        archiveTimeStampObject.setTimestampToken(getTimestampToken(archiveTimeStamp));
        archiveTimeStampObject.setOrder(order);
        // cryptographic info not applicable for ANS.1
        return archiveTimeStampObject;
    }
    
    private TimestampToken getTimestampToken(ArchiveTimeStamp archiveTimeStamp) {
    	ContentInfo contentInfo = archiveTimeStamp.getTimeStamp();
        if (contentInfo == null) {
            throw new IllegalInputException("TimeStampToken shall be defined!");
        }
        try {
            return new TimestampToken(contentInfo.getEncoded(), TimestampType.EVIDENCE_RECORD_TIMESTAMP);
        } catch (Exception e) {
            LOG.warn("Unable to create a time-stamp token. Reason : {}", e.getMessage(), e);
            return null;
        }
    }
    
    private List<ASN1SequenceObject> getHashTree(ArchiveTimeStamp archiveTimeStamp) {
        final PartialHashtree[] hashTree = archiveTimeStamp.getReducedHashTree();
        if (hashTree != null && hashTree.length > 0) {
        	ASN1SequenceObject[] result = new ASN1SequenceObject[hashTree.length];
            for (int i = 0; i < hashTree.length; i++) {
                final PartialHashtree partialHashtree = hashTree[i];
                ASN1SequenceObject digestValueGroup = getDigestValueGroup(partialHashtree, i+1);
                result[i] = digestValueGroup;
            }
            return Arrays.asList(result);
        }
        return Collections.emptyList();
    }

    private ASN1SequenceObject getDigestValueGroup(PartialHashtree partialHashtree, int order) {
    	ASN1SequenceObject digestValueGroup = new ASN1SequenceObject(partialHashtree);
        digestValueGroup.setDigestValues(getDigestValues(partialHashtree));
        digestValueGroup.setOrder(order);
        return digestValueGroup;
    }
    
    private List<byte[]> getDigestValues(PartialHashtree partialHashtree) {
        List<byte[]> result = new ArrayList<>();

        final byte[][] digestValueList = partialHashtree.getValues();
        for (int i = 0; i < partialHashtree.getValueCount(); i++) {
            final byte[] digestValue = digestValueList[i];
            result.add(digestValue);
        }

        return result;
    }

}
