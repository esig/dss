package eu.europa.esig.dss.evidencerecord.asn1.validation;

import eu.europa.esig.dss.evidencerecord.common.validation.ArchiveTimeStampChainObject;
import org.bouncycastle.asn1.tsp.ArchiveTimeStampChain;

/**
 * The ASN1 Evidence Record representation of ArchiveTimeStampChain object
 *
 */
public class ASN1ArchiveTimeStampChainObject extends ArchiveTimeStampChainObject implements ASN1EvidenceRecordObject {

	private static final long serialVersionUID = 1027914551003735835L;

	/** The current ArchiveTimeStampChain */
    private final ArchiveTimeStampChain archiveTimeStampChain;

    /**
     * Default constructor
     *
     * @param archiveTimeStampChain {@link ArchiveTimeStampChain}
     */
    public ASN1ArchiveTimeStampChainObject(final ArchiveTimeStampChain archiveTimeStampChain) {
        this.archiveTimeStampChain = archiveTimeStampChain;
    }

}
