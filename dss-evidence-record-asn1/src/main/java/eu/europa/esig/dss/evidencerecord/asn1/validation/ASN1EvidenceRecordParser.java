package eu.europa.esig.dss.evidencerecord.asn1.validation;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.tsp.ArchiveTimeStamp;
import org.bouncycastle.asn1.tsp.ArchiveTimeStampChain;
import org.bouncycastle.asn1.tsp.ArchiveTimeStampSequence;
import org.bouncycastle.asn1.tsp.EvidenceRecord;
import org.bouncycastle.asn1.tsp.PartialHashtree;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.evidencerecord.common.validation.ArchiveTimeStampObject;
import eu.europa.esig.dss.evidencerecord.common.validation.CryptographicInformation;
import eu.europa.esig.dss.evidencerecord.common.validation.EvidenceRecordParser;
import eu.europa.esig.dss.exception.IllegalInputException;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;

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
                final ArchiveTimeStampChain archiveTimeStampChainElement = (ArchiveTimeStampChain) archiveTimeStampSequenceList.getArchiveTimeStampChains()[i];
                ASN1ArchiveTimeStampChainObject archiveTimeStampChain = getASN1ArchiveTimeStampChainObject(archiveTimeStampChainElement, i+1);
                result[i] = archiveTimeStampChain;
            }
            return Arrays.asList(result);
        }

        return Collections.emptyList();
    }
    
    private ASN1ArchiveTimeStampChainObject getASN1ArchiveTimeStampChainObject(ArchiveTimeStampChain archiveTimeStampChain, int order) {
    	ASN1ArchiveTimeStampChainObject archiveTimeStampChainObject = new ASN1ArchiveTimeStampChainObject(archiveTimeStampChain);
        archiveTimeStampChainObject.setDigestAlgorithm(getDigestAlgorithm(archiveTimeStampChain));
//        archiveTimeStampChainObject.setCanonicalizationMethod(getCanonicalizationMethod(archiveTimeStampChain));
        archiveTimeStampChainObject.setOrder(order);
        archiveTimeStampChainObject.setArchiveTimeStamps(getASN1ArchiveTimeStamps(archiveTimeStampChain));
        return archiveTimeStampChainObject;
    }
    
    private DigestAlgorithm getDigestAlgorithm(ArchiveTimeStampChain archiveTimeStampChainElement) {
    	// TODO!? Where to take the alg from? First Element?
    	AlgorithmIdentifier algIdentifier = archiveTimeStampChainElement.getArchiveTimestamps()[0].getDigestAlgorithmIdentifier();
        return DigestAlgorithm.forOID(algIdentifier.getAlgorithm().getId());
    }

    private List<? extends ArchiveTimeStampObject> getASN1ArchiveTimeStamps(ArchiveTimeStampChain archiveTimeStampChain) {
        final ArchiveTimeStamp[] archiveTimeStampList = archiveTimeStampChain.getArchiveTimestamps();
        if (archiveTimeStampList != null && archiveTimeStampList.length > 0) {
        	ASN1ArchiveTimeStampObject[] result = new ASN1ArchiveTimeStampObject[archiveTimeStampList.length];
            for (int i = 0; i < archiveTimeStampList.length; i++) {
                final ArchiveTimeStamp archiveTimeStampElement = (ArchiveTimeStamp) archiveTimeStampList[i];
                ASN1ArchiveTimeStampObject archiveTimeStamp = getASN1ArchiveTimeStampObject(archiveTimeStampElement, i+1);
                result[i] = archiveTimeStamp;
            }
            return Arrays.asList(result);
        }
        return Collections.emptyList();
    }
    
    private ASN1ArchiveTimeStampObject getASN1ArchiveTimeStampObject(ArchiveTimeStamp archiveTimeStampElement, int order) {
    	ASN1ArchiveTimeStampObject archiveTimeStampObject = new ASN1ArchiveTimeStampObject(archiveTimeStampElement);
        archiveTimeStampObject.setHashTree(getHashTree(archiveTimeStampElement));
        archiveTimeStampObject.setTimestampToken(getTimestampToken(archiveTimeStampElement));
        archiveTimeStampObject.setCryptographicInformationList(getCryptographicInformationList(archiveTimeStampElement));
        archiveTimeStampObject.setOrder(order);
        return archiveTimeStampObject;
    }
    
    private TimestampToken getTimestampToken(ArchiveTimeStamp archiveTimeStampElement) {
    	ContentInfo timeStampTokenElement = archiveTimeStampElement.getTimeStamp();
        if (timeStampTokenElement == null) {
            throw new IllegalInputException("TimeStampToken shall be defined!");
        }
        try {
            return new TimestampToken(timeStampTokenElement.getEncoded(), TimestampType.EVIDENCE_RECORD_TIMESTAMP);
        } catch (Exception e) {
            LOG.warn("Unable to create a time-stamp token. Reason : {}", e.getMessage(), e);
            return null;
        }
    }
    
    private List<ASN1SequenceObject> getHashTree(ArchiveTimeStamp archiveTimeStampElement) {
        final PartialHashtree[] hashTree = archiveTimeStampElement.getReducedHashTree();
        if (hashTree != null && hashTree.length > 0) {
        	ASN1SequenceObject[] result = new ASN1SequenceObject[hashTree.length];
            for (int i = 0; i < hashTree.length; i++) {
                final PartialHashtree sequenceElement = (PartialHashtree) hashTree[i];
                ASN1SequenceObject digestValueGroup = getDigestValueGroup(sequenceElement, i+1);
                result[i] = digestValueGroup;
            }
            return Arrays.asList(result);
        }
        return Collections.emptyList();
    }

    private ASN1SequenceObject getDigestValueGroup(PartialHashtree sequenceElement, int order) {
    	ASN1SequenceObject digestValueGroup = new ASN1SequenceObject(sequenceElement);
        digestValueGroup.setDigestValues(getDigestValues(sequenceElement));
        digestValueGroup.setOrder(order);
        return digestValueGroup;
    }
    
    private List<byte[]> getDigestValues(PartialHashtree sequenceElement) {
        List<byte[]> result = new ArrayList<>();

        final byte[][] digestValueList = sequenceElement.getValues();
        for (int i = 0; i < sequenceElement.getValueCount(); i++) {
            final byte[] digestValueElement = digestValueList[i];
            result.add(digestValueElement);
        }

        return result;
    }
    
    // TODO: What is this for and where to get it?
    private List<CryptographicInformation> getCryptographicInformationList(ArchiveTimeStamp archiveTimeStampElement) {
//        NodeList cryptographicInformationNodeList = DomUtils.getNodeList(archiveTimeStampElement, XMLERSPath.CRYPTOGRAPHIC_INFORMATION_PATH);
//        if (cryptographicInformationNodeList == null || cryptographicInformationNodeList.getLength() == 0) {
//            return Collections.emptyList();
//        }

        final List<CryptographicInformation> cryptographicInformationList = new ArrayList<>();
//        for (int i = 0; i < cryptographicInformationNodeList.getLength(); i++) {
//            Element cryptographicInformationElement = (Element) cryptographicInformationNodeList.item(i);
//            String type = cryptographicInformationElement.getAttribute(XMLERSAttribute.TYPE.getAttributeName());
//            if (Utils.isStringEmpty(type)) {
//                LOG.warn("Type attribute shall be defined within CryptographicInformation element! Element is skipped.");
//                continue;
//            }
//            CryptographicInformationType cryptographicInformationType = CryptographicInformationType.fromLabel(type);
//
//            String textContent = cryptographicInformationElement.getTextContent();
//            if (!Utils.isBase64Encoded(textContent)) {
//                LOG.warn("Value within CryptographicInformation element shall be base64-encoded! Element is skipped.");
//                continue;
//            }
//
//            cryptographicInformationList.add(
//                    new CryptographicInformation(Utils.fromBase64(textContent), cryptographicInformationType));
//        }

        return cryptographicInformationList;
    }

}
