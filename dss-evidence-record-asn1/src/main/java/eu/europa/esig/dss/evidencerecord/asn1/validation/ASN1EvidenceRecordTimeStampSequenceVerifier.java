package eu.europa.esig.dss.evidencerecord.asn1.validation;

import java.io.IOException;

import org.bouncycastle.asn1.tsp.ArchiveTimeStampChain;
import org.bouncycastle.asn1.tsp.ArchiveTimeStampSequence;
import org.bouncycastle.asn1.tsp.EvidenceRecord;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.evidencerecord.common.validation.ArchiveTimeStampChainObject;
import eu.europa.esig.dss.evidencerecord.common.validation.ArchiveTimeStampObject;
import eu.europa.esig.dss.evidencerecord.common.validation.EvidenceRecordTimeStampSequenceVerifier;
import eu.europa.esig.dss.model.DSSMessageDigest;
import eu.europa.esig.dss.spi.DSSUtils;

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

    // TODO: !?
    @Override
    protected DSSMessageDigest computeTimeStampHash(DigestAlgorithm digestAlgorithm,
    		ArchiveTimeStampObject archiveTimeStamp, ArchiveTimeStampChainObject archiveTimeStampChain) {
	    ASN1ArchiveTimeStampObject asn1ArchiveTimeStampObject = (ASN1ArchiveTimeStampObject) archiveTimeStamp;
	    byte[] digestValue = DSSUtils.digest(digestAlgorithm, asn1ArchiveTimeStampObject.getTimestampToken().getEncoded());
	    return new DSSMessageDigest(digestAlgorithm, digestValue);
    }

    @Override
    protected DSSMessageDigest computePrecedingTimeStampSequenceHash(DigestAlgorithm digestAlgorithm, ArchiveTimeStampChainObject archiveTimeStampChain) {
        ASN1ArchiveTimeStampChainObject asn1ArchiveTimeStampChainObject = (ASN1ArchiveTimeStampChainObject) archiveTimeStampChain;

        ArchiveTimeStampSequence archiveTimeStampSequence = getArchiveTimeStampSequence();
        ArchiveTimeStampChain[] childNodes = archiveTimeStampSequence.getArchiveTimeStampChains();
        ArchiveTimeStampChain[] precedingchildNodes = new ArchiveTimeStampChain[asn1ArchiveTimeStampChainObject.getOrder() - 1];
        for (int i = 0; i < childNodes.length; i++) {
            if (i < (asn1ArchiveTimeStampChainObject.getOrder()-1)) {
            	precedingchildNodes[i] = childNodes[i];
            }
        }
        
        ArchiveTimeStampSequence precedingarchiveTimeStampSequence = new ArchiveTimeStampSequence(precedingchildNodes);
        byte[] digestValue = null;
		try {
			digestValue = DSSUtils.digest( digestAlgorithm, precedingarchiveTimeStampSequence.toASN1Primitive().getEncoded() );
		} catch (IOException e) {
			LOG.warn("Unable to generate ASN1 TimeStampSequence. Reason : {}", e.getMessage(), e);
			return null;
		}
		
		// TODO:
		// get the new Document Hash
		// sort both Hashes in ascending Order
		// and digest the concat Hashvalue
		
        return new DSSMessageDigest(digestAlgorithm, digestValue);
    }
    
    private ArchiveTimeStampSequence getArchiveTimeStampSequence() {
    	ASN1EvidenceRecord asn1EvidenceRecord = (ASN1EvidenceRecord) evidenceRecord;
    	EvidenceRecord evidenceRecord = asn1EvidenceRecord.getEvidenceRecordElement();
        return evidenceRecord.getArchiveTimeStampSequence();
    }

}
