package eu.europa.esig.dss.cades;

import java.io.Serializable;
import java.util.Comparator;

/**
 * The class is used to compare production time of {@code org.bouncycastle.asn1.tsp.EvidenceRecord}s
 * Class checks the generation time of evidence records
 * <p>
 * The method compare() returns
 *     -1 if the {@code evidenceRecordOne} was created before {@code evidenceRecordTwo}
 *     0 if EvidenceRecord's were created at the same time
 *     1 if the {@code evidenceRecordOne} was created after {@code evidenceRecordTwo}
 *
 */
public class EvidenceRecordProductionComparator implements Comparator<org.bouncycastle.asn1.tsp.EvidenceRecord>, Serializable {

    private static final long serialVersionUID = 7426569998197138099L;

    /**
     * Default constructor
     */
    public EvidenceRecordProductionComparator() {
        // empty
    }

    @Override
    public int compare(org.bouncycastle.asn1.tsp.EvidenceRecord evidenceRecordOne, org.bouncycastle.asn1.tsp.EvidenceRecord evidenceRecordTwo) {
        return compareByGenerationTime(evidenceRecordOne, evidenceRecordTwo);
    }

    private int compareByGenerationTime(org.bouncycastle.asn1.tsp.EvidenceRecord evidenceRecordOne, org.bouncycastle.asn1.tsp.EvidenceRecord evidenceRecordTwo) {
        return CAdESUtils.getEvidenceRecordGenerationTime(evidenceRecordOne).compareTo(CAdESUtils.getEvidenceRecordGenerationTime(evidenceRecordTwo));
    }

}
