package eu.europa.esig.dss.evidencerecord.asn1.validation;

import org.bouncycastle.asn1.tsp.ArchiveTimeStamp;

import eu.europa.esig.dss.evidencerecord.common.validation.ArchiveTimeStampObject;

/**
 * The ASN1 Evidence Record representation of ArchiveTimeStamp object
 *
 */
public class ASN1ArchiveTimeStampObject extends ArchiveTimeStampObject implements ASN1EvidenceRecordObject {
    
	private static final long serialVersionUID = 2496285566554079215L;

	/** The current ArchiveTimeStamp */
    private final ArchiveTimeStamp archiveTimeStamp;

    /**
     * Default constructor
     *
     * @param archiveTimeStamp {@link ArchiveTimeStamp}
     */
    public ASN1ArchiveTimeStampObject(final ArchiveTimeStamp archiveTimeStamp) {
        this.archiveTimeStamp = archiveTimeStamp;
    }
}
