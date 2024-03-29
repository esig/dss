package eu.europa.esig.dss.evidencerecord.asn1.digest;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.evidencerecord.asn1.validation.ASN1EvidenceRecord;
import eu.europa.esig.dss.evidencerecord.common.digest.AbstractEvidenceRecordRenewalDigestBuilder;
import eu.europa.esig.dss.evidencerecord.common.validation.ArchiveTimeStampChainObject;
import eu.europa.esig.dss.evidencerecord.common.validation.ArchiveTimeStampObject;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSMessageDigest;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.utils.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;

/**
 * This class builds digest for an RFC 4998 ERS evidence record's renewal
 *
 */
public class ASN1EvidenceRecordRenewalDigestBuilder extends AbstractEvidenceRecordRenewalDigestBuilder {

    private static final Logger LOG = LoggerFactory.getLogger(ASN1EvidenceRecordRenewalDigestBuilder.class);

    /**
     * Creates an instance of {@code ASN1EvidenceRecordRenewalDigestBuilder} allowing to build hash for
     * ASN.1 evidence record {@code document}'s renewal.
     * Builds digest for the last available ArchiveTimeStamp or ArchiveTimeStampChain, based on the called method.
     *
     * @param document {@link DSSDocument}
     */
    public ASN1EvidenceRecordRenewalDigestBuilder(final DSSDocument document) {
        this(new ASN1EvidenceRecord(document));
    }

    /**
     * Creates an instance of {@code ASN1EvidenceRecordRenewalDigestBuilder} allowing to build hash for
     * ASN.1 evidence record {@code document}'s renewal, with the provided {@code digestAlgorithm} (see note below).
     * Builds digest for the last available ArchiveTimeStamp or ArchiveTimeStampChain, based on the called method.
     * NOTE: time-stamp renewal uses digest algorithm extracted from the last ArchiveTimeStampChain.
     *
     * @param document {@link DSSDocument}
     * @param digestAlgorithm {@link DigestAlgorithm} to be used on hash-tree renewal hash computation
     */
    public ASN1EvidenceRecordRenewalDigestBuilder(final DSSDocument document, final DigestAlgorithm digestAlgorithm) {
        this(new ASN1EvidenceRecord(document), digestAlgorithm);
    }

    /**
     * Creates an instance of {@code ASN1EvidenceRecordRenewalDigestBuilder} allowing to build hash for
     * {@code ASN1EvidenceRecord}'s renewal, with a default SHA256 digest algorithm to be used on hash-tree
     * renewal computation (see note).
     * Builds digest for the last available ArchiveTimeStamp or ArchiveTimeStampChain, based on the called method.
     * NOTE: time-stamp renewal uses digest algorithm extracted from the last ArchiveTimeStampChain.
     *
     * @param asn1EvidenceRecord {@link ASN1EvidenceRecord}
     */
    public ASN1EvidenceRecordRenewalDigestBuilder(final ASN1EvidenceRecord asn1EvidenceRecord) {
        super(asn1EvidenceRecord);
    }

    /**
     * Creates an instance of {@code XMLEvidenceRecordRenewalDigestBuilder} allowing to build hash for
     * {@code XmlEvidenceRecord}'s renewal, with the provided {@code digestAlgorithm} (see note below).
     * Builds digest for the last available ArchiveTimeStamp or ArchiveTimeStampChain, based on the called method.
     * NOTE: time-stamp renewal uses digest algorithm extracted from the last ArchiveTimeStampChain.
     *
     * @param asn1EvidenceRecord {@link ASN1EvidenceRecord}
     * @param digestAlgorithm {@link DigestAlgorithm} to be used on hash-tree renewal hash computation
     */
    public ASN1EvidenceRecordRenewalDigestBuilder(final ASN1EvidenceRecord asn1EvidenceRecord, final DigestAlgorithm digestAlgorithm) {
        super(asn1EvidenceRecord, digestAlgorithm);
    }

    @Override
    public ASN1EvidenceRecordRenewalDigestBuilder setDetachedContent(List<DSSDocument> detachedContent) {
        return (ASN1EvidenceRecordRenewalDigestBuilder) super.setDetachedContent(detachedContent);
    }

    @Override
    public DSSMessageDigest buildTimeStampRenewalDigest() {
        ArchiveTimeStampObject archiveTimeStampObject = getLastArchiveTimeStampObject();
        return getArchiveTimeStampSequenceDigestHelper().buildTimeStampRenewalDigest(archiveTimeStampObject);
    }

    @Override
    public List<Digest> buildHashTreeRenewalDigestGroup() {
        final List<Digest> result = new ArrayList<>();
        if (Utils.isCollectionNotEmpty(detachedContent)) {
            ArchiveTimeStampChainObject lastArchiveTimeStampChainObject = getLastArchiveTimeStampChainObject();
            Digest lastTimeStampSequenceHash = getArchiveTimeStampSequenceDigestHelper()
                    .buildArchiveTimeStampSequenceDigest(digestAlgorithm, lastArchiveTimeStampChainObject.getOrder() + 1);
            for (DSSDocument document : detachedContent) {
                DSSMessageDigest chainAndDocumentHash = getArchiveTimeStampSequenceDigestHelper()
                        .computeChainAndDocumentHash(lastTimeStampSequenceHash, document);
                result.add(new DSSMessageDigest(digestAlgorithm, chainAndDocumentHash.getValue()));
            }
        } else {
            LOG.warn("No detached content have been provided! Computation of digest for hash-tree renewal is skipped.");
        }
        return result;
    }

    /**
     * This method returns a helper class containing supporting methods for digest computation in relation
     * to an archive-time-stamp-sequence
     *
     * @return {@link ASN1ArchiveTimeStampSequenceDigestHelper}
     */
    protected ASN1ArchiveTimeStampSequenceDigestHelper getArchiveTimeStampSequenceDigestHelper() {
        return new ASN1ArchiveTimeStampSequenceDigestHelper((ASN1EvidenceRecord) evidenceRecord);
    }

}
