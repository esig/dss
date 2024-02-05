package eu.europa.esig.dss.evidencerecord.asn1.validation;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.evidencerecord.common.validation.ArchiveTimeStampObject;
import org.bouncycastle.asn1.tsp.ArchiveTimeStamp;

/**
 * The ASN1 Evidence Record representation of ArchiveTimeStamp object
 *
 */
public class ASN1ArchiveTimeStampObject extends ArchiveTimeStampObject implements ASN1EvidenceRecordObject {
    
	private static final long serialVersionUID = 2496285566554079215L;

	/** The current ArchiveTimeStamp */
    private final ArchiveTimeStamp archiveTimeStamp;

    /** Digest algorithm defined within ArchiveTimeStamp object */
    private DigestAlgorithm digestAlgorithm;

    /**
     * Default constructor
     *
     * @param archiveTimeStamp {@link ArchiveTimeStamp}
     */
    public ASN1ArchiveTimeStampObject(final ArchiveTimeStamp archiveTimeStamp) {
        this.archiveTimeStamp = archiveTimeStamp;
    }

    /**
     * Gets the {@code DigestAlgorithm}
     *
     * @return {@link DigestAlgorithm}
     */
    public DigestAlgorithm getDigestAlgorithm() {
        return digestAlgorithm;
    }

    /**
     * Sets the {@code DigestAlgorithm}
     *
     * @param digestAlgorithm {@link DigestAlgorithm}
     */
    public void setDigestAlgorithm(DigestAlgorithm digestAlgorithm) {
        this.digestAlgorithm = digestAlgorithm;
    }

}
