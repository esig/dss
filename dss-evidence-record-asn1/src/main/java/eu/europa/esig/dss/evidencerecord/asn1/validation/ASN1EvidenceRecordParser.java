package eu.europa.esig.dss.evidencerecord.asn1.validation;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.bouncycastle.asn1.tsp.ArchiveTimeStamp;
import org.bouncycastle.asn1.tsp.ArchiveTimeStampChain;
import org.bouncycastle.asn1.tsp.ArchiveTimeStampSequence;
import org.bouncycastle.asn1.tsp.EvidenceRecord;
import org.bouncycastle.asn1.tsp.PartialHashtree;

import eu.europa.esig.dss.evidencerecord.common.validation.ArchiveTimeStampObject;
import eu.europa.esig.dss.evidencerecord.common.validation.EvidenceRecordParser;

/**
 * This class is used to parse an ASN.1 Evidence Record
 *
 */
public class ASN1EvidenceRecordParser implements EvidenceRecordParser {

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
                final ArchiveTimeStampChain archiveTimeStampChainElement = (ArchiveTimeStampChain) archiveTimeStampSequenceList.getArchiveTimeStampChains()[i];
                ASN1ArchiveTimeStampChainObject archiveTimeStampChain = getASN1ArchiveTimeStampChainObject(archiveTimeStampChainElement);
//                int order = archiveTimeStampChain.getOrder();
//                // TODO : verify order validity
//                result[order - 1] = archiveTimeStampChain;
                result[i] = archiveTimeStampChain;
            }
            return Arrays.asList(result);
        }

        return Collections.emptyList();
    }
    
    private ASN1ArchiveTimeStampChainObject getASN1ArchiveTimeStampChainObject(ArchiveTimeStampChain archiveTimeStampChain) {
    	ASN1ArchiveTimeStampChainObject archiveTimeStampChainObject = new ASN1ArchiveTimeStampChainObject(archiveTimeStampChain);
//        archiveTimeStampChainObject.setDigestAlgorithm(getDigestAlgorithm(archiveTimeStampChain));
//        archiveTimeStampChainObject.setCanonicalizationMethod(getCanonicalizationMethod(archiveTimeStampChain));
//        archiveTimeStampChainObject.setOrder(getOrderAttributeValue(archiveTimeStampChain));
        archiveTimeStampChainObject.setArchiveTimeStamps(getASN1ArchiveTimeStamps(archiveTimeStampChain));
        return archiveTimeStampChainObject;
    }

    private List<? extends ArchiveTimeStampObject> getASN1ArchiveTimeStamps(ArchiveTimeStampChain archiveTimeStampChain) {
        final ArchiveTimeStamp[] archiveTimeStampList = archiveTimeStampChain.getArchiveTimestamps();
        if (archiveTimeStampList != null && archiveTimeStampList.length > 0) {
        	ASN1ArchiveTimeStampObject[] result = new ASN1ArchiveTimeStampObject[archiveTimeStampList.length];
            for (int i = 0; i < archiveTimeStampList.length; i++) {
                final ArchiveTimeStamp archiveTimeStampElement = (ArchiveTimeStamp) archiveTimeStampList[i];
                ASN1ArchiveTimeStampObject archiveTimeStamp = getASN1ArchiveTimeStampObject(archiveTimeStampElement);
//                int order = archiveTimeStamp.getOrder();
//                result[order - 1] = archiveTimeStamp;
                result[i] = archiveTimeStamp;
            }
            return Arrays.asList(result);
        }
        return Collections.emptyList();
    }
    
    private ASN1ArchiveTimeStampObject getASN1ArchiveTimeStampObject(ArchiveTimeStamp archiveTimeStampElement) {
    	ASN1ArchiveTimeStampObject archiveTimeStampObject = new ASN1ArchiveTimeStampObject(archiveTimeStampElement);
        archiveTimeStampObject.setHashTree(getHashTree(archiveTimeStampElement));
//        archiveTimeStampObject.setTimestampToken(getTimestampToken(archiveTimeStampElement));
//        archiveTimeStampObject.setCryptographicInformationList(getCryptographicInformationList(archiveTimeStampElement));
//        archiveTimeStampObject.setOrder(getOrderAttributeValue(archiveTimeStampElement));
        return archiveTimeStampObject;
    }
    
    private List<ASN1SequenceObject> getHashTree(ArchiveTimeStamp archiveTimeStampElement) {
        final PartialHashtree[] hashTree = archiveTimeStampElement.getReducedHashTree();
        if (hashTree != null && hashTree.length > 0) {
        	ASN1SequenceObject[] result = new ASN1SequenceObject[hashTree.length];
            for (int i = 0; i < hashTree.length; i++) {
                final PartialHashtree sequenceElement = (PartialHashtree) hashTree[i];
                ASN1SequenceObject digestValueGroup = getDigestValueGroup(sequenceElement);
//                int order = digestValueGroup.getOrder();
//                result[order - 1] = digestValueGroup;
                result[i] = digestValueGroup;
            }
            return Arrays.asList(result);
        }
        return Collections.emptyList();
    }

    private ASN1SequenceObject getDigestValueGroup(PartialHashtree sequenceElement) {
    	ASN1SequenceObject digestValueGroup = new ASN1SequenceObject(sequenceElement);
//        digestValueGroup.setDigestValues(getDigestValues(sequenceElement));
//        digestValueGroup.setOrder(getOrderAttributeValue(sequenceElement));
        return digestValueGroup;
    }
}
