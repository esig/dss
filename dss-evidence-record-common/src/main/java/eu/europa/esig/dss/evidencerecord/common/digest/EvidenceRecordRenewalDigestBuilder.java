package eu.europa.esig.dss.evidencerecord.common.digest;

import eu.europa.esig.dss.model.Digest;

import java.util.List;

/**
 * Builds digest(s) required for a renewal of an evidence-record.
 * NOTE: Does not perform validation of the evidence record
 *
 */
public interface EvidenceRecordRenewalDigestBuilder {

    /**
     * This method builds digest for a time-stamp renewal
     *
     * @return {@link Digest}
     */
    Digest buildTimeStampRenewalDigest();

    /**
     * This method builds digest for a hash-tree renewal.
     * NOTE: the corresponding detached contents may be required to be provided
     *
     * @return a list of {@link Digest}s
     */
    List<Digest> buildHashTreeRenewalDigestGroup();

}
