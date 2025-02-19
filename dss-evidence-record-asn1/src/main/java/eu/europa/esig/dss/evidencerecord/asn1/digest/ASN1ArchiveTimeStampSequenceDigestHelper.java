/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.evidencerecord.asn1.digest;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.evidencerecord.asn1.validation.ASN1ArchiveTimeStampObject;
import eu.europa.esig.dss.evidencerecord.asn1.validation.ASN1EvidenceRecord;
import eu.europa.esig.dss.evidencerecord.common.digest.AbstractEvidenceRecordRenewalDigestBuilderHelper;
import eu.europa.esig.dss.evidencerecord.common.validation.ArchiveTimeStampChainObject;
import eu.europa.esig.dss.evidencerecord.common.validation.ArchiveTimeStampObject;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSMessageDigest;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.spi.DSSMessageDigestCalculator;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import org.bouncycastle.asn1.tsp.ArchiveTimeStampChain;
import org.bouncycastle.asn1.tsp.ArchiveTimeStampSequence;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * This class contains supporting method for ERS evidence record renewal
 *
 */
public class ASN1ArchiveTimeStampSequenceDigestHelper extends AbstractEvidenceRecordRenewalDigestBuilderHelper {

    private static final Logger LOG = LoggerFactory.getLogger(ASN1ArchiveTimeStampSequenceDigestHelper.class);

    /**
     * Default constructor
     *
     * @param evidenceRecord {@link ASN1EvidenceRecord}
     */
    public ASN1ArchiveTimeStampSequenceDigestHelper(final ASN1EvidenceRecord evidenceRecord) {
        super(evidenceRecord);
    }

    @Override
    public DSSMessageDigest buildTimeStampRenewalDigest(ArchiveTimeStampObject archiveTimeStamp) {
        ArchiveTimeStampChainObject archiveTimeStampChain = getArchiveTimeStampChainObject(archiveTimeStamp);
        return buildTimeStampRenewalDigest(archiveTimeStamp, archiveTimeStampChain.getDigestAlgorithm());
    }

    /**
     * This method builds digest for a time-stamp renewal with the specified {@code digestAlgorithm}
     *
     * @param archiveTimeStamp {@link ArchiveTimeStampObject} to build digest on
     * @param digestAlgorithm {@link DigestAlgorithm} to be used on digest computation
     * @return {@link Digest}
     */
    public DSSMessageDigest buildTimeStampRenewalDigest(ArchiveTimeStampObject archiveTimeStamp, DigestAlgorithm digestAlgorithm) {
        ASN1ArchiveTimeStampObject asn1ArchiveTimeStampObject = (ASN1ArchiveTimeStampObject) archiveTimeStamp;
        byte[] digestValue = DSSUtils.digest(digestAlgorithm, asn1ArchiveTimeStampObject.getTimestampToken().getEncoded());
        return new DSSMessageDigest(digestAlgorithm, digestValue);
    }

    @Override
    public DSSMessageDigest buildArchiveTimeStampSequenceDigest(ArchiveTimeStampChainObject archiveTimeStampChain) {
        ArchiveTimeStampChainObject nextArchiveTimeStampChain = getNextArchiveTimeStampChain(archiveTimeStampChain);
        return buildArchiveTimeStampSequenceDigest(nextArchiveTimeStampChain.getDigestAlgorithm(), nextArchiveTimeStampChain.getOrder());
    }

    /**
     * This method builds digest for a time-stamp chain renewal with the specified {@code digestAlgorithm}
     *
     * @param digestAlgorithm {@link DigestAlgorithm} to be used for digest calculation
     * @param archiveTimeStampChainOrder order value of the last archive time-stamp chain
     *                                   to be concatenated for digest computation
     * @return {@link DSSMessageDigest}
     */
    public DSSMessageDigest buildArchiveTimeStampSequenceDigest(DigestAlgorithm digestAlgorithm, int archiveTimeStampChainOrder) {
        archiveTimeStampChainOrder = archiveTimeStampChainOrder - 1;

        ArchiveTimeStampSequence archiveTimeStampSequence = getArchiveTimeStampSequence();
        ArchiveTimeStampChain[] childNodes = archiveTimeStampSequence.getArchiveTimeStampChains();
        ArchiveTimeStampChain[] archiveTimeStampChain = new ArchiveTimeStampChain[archiveTimeStampChainOrder];
        for (int i = 0; i < childNodes.length; i++) {
            if (i < archiveTimeStampChainOrder) {
                archiveTimeStampChain[i] = childNodes[i];
            }
        }

        // calc the preceding ATSSeq hash
        ArchiveTimeStampSequence recreatedArchiveTimeStampSequence = new ArchiveTimeStampSequence(archiveTimeStampChain);
        try {
            return new DSSMessageDigest(digestAlgorithm,
                    DSSUtils.digest(digestAlgorithm, recreatedArchiveTimeStampSequence.toASN1Primitive().getEncoded()));
        } catch (IOException e) {
            LOG.warn("Unable to generate ASN1 TimeStampSequence. Reason : {}", e.getMessage(), e);
            return null;
        }
    }

    private ArchiveTimeStampSequence getArchiveTimeStampSequence() {
        ASN1EvidenceRecord asn1EvidenceRecord = (ASN1EvidenceRecord) evidenceRecord;
        return asn1EvidenceRecord.getEvidenceRecord().getArchiveTimeStampSequence();
    }

    /**
     * Computes a hash value for chain-hash and document-hash
     *
     * @param archiveTimeStampChainHash {@link Digest} hash of the previous ArchiveTimeStampChain
     * @param document {@link DSSDocument} detached document
     * @return {@link DSSMessageDigest}
     */
    public DSSMessageDigest computeChainAndDocumentHash(Digest archiveTimeStampChainHash,
                                                        DSSDocument document) {
        DigestAlgorithm digestAlgorithm = archiveTimeStampChainHash.getAlgorithm();

        /*
         * The algorithm by which a root hash value is generated from the
         * <HashTree> element is as follows: the content of each <DigestValue>
         * element within the first <Sequence> element is base64 ([RFC4648],
         * using the base64 alphabet not the base64url alphabet) decoded to
         * obtain a binary value (representing the hash value). All collected
         * hash values from the sequence are [ordered in binary ascending order],
         * concatenated and a new hash value is generated from that string.
         * With one exception to this rule: when the first <Sequence> element
         * has only one <DigestValue> element, then its binary value is added to
         * the next list obtained from the next <Sequence> element.
         */

        // 0. Compute hash of the document
        byte[] documentMessageDigest = document.getDigestValue(digestAlgorithm);

        // 1. Group together items
        List<byte[]> hashValueList = new ArrayList<>();
        hashValueList.add(documentMessageDigest);
        hashValueList.add(archiveTimeStampChainHash.getValue());

        // 2a. Exception
        if (Utils.collectionSize(hashValueList) == 1) {
            return new DSSMessageDigest(digestAlgorithm, hashValueList.get(0));
        }

        /*
         * All known ASN.1 ERs are not sorted for this hash!
         *
         * There is an error in Figure 4 of RFC4998, which states
         * "h1' = H( binary sorted and concatenated (H(d1), ha(1)))",
         * but 5.2. point 4. clearly states "Concatenate each h(i)
         * with ha(i) and generate hash values h(i)' = H (h(i)+ ha(i)).".
         * N.b.: There is no need to sort hashes when their order is defined.
         *
         * Read more here: <a href="https://github.com/de-bund-bsi-tr-esor/ERVerifyTool/issues/2">https://github.com/de-bund-bsi-tr-esor/ERVerifyTool/issues/2</a>
         */
        // 2b. Binary ascending sort
        // hashValueList.sort(ByteArrayComparator.getInstance());

        // 3. Concatenate
        final DSSMessageDigestCalculator digestCalculator = new DSSMessageDigestCalculator(digestAlgorithm);
        for (byte[] hashValue : hashValueList) {
            digestCalculator.update(hashValue);
        }
        // 4. Calculate hash value
        return digestCalculator.getMessageDigest(digestAlgorithm);
    }

}
