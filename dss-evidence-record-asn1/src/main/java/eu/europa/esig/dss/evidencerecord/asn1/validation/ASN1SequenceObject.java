package eu.europa.esig.dss.evidencerecord.asn1.validation;

import eu.europa.esig.dss.evidencerecord.common.validation.DigestValueGroup;
import org.bouncycastle.asn1.tsp.PartialHashtree;

public class ASN1SequenceObject extends DigestValueGroup implements ASN1EvidenceRecordObject {

	private static final long serialVersionUID = -747779213316560098L;

	/** The current partial hash tree object */
    private final PartialHashtree partialHashtree;

    /**
     * Default constructor
     *
     * @param partialHashtree {@link PartialHashtree}
     */
    public ASN1SequenceObject(final PartialHashtree partialHashtree) {
        this.partialHashtree = partialHashtree;
    }

}