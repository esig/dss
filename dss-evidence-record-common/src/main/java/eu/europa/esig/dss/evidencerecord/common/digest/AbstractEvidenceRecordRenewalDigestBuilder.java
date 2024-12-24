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
package eu.europa.esig.dss.evidencerecord.common.digest;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.evidencerecord.common.validation.ArchiveTimeStampChainObject;
import eu.europa.esig.dss.evidencerecord.common.validation.ArchiveTimeStampObject;
import eu.europa.esig.dss.evidencerecord.common.validation.DefaultEvidenceRecord;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSMessageDigest;

import java.util.List;
import java.util.Objects;

/**
 * Abstract implementation of {@code EvidenceRecordRenewalDigestBuilder}.
 * Contains common methods for digest computation for evidence record's renewal.
 *
 */
public abstract class AbstractEvidenceRecordRenewalDigestBuilder implements EvidenceRecordRenewalDigestBuilder {

    /**
     * Evidence record to compute digest for
     */
    protected final DefaultEvidenceRecord evidenceRecord;

    /**
     * The digest algorithm to be used on hash computation for time-stamp chain renewal.
     * Default : DigestAlgorithm.SHA256
     */
    protected final DigestAlgorithm digestAlgorithm;

    /**
     * List of documents to compute hashes for
     */
    protected List<DSSDocument> detachedContent;

    /**
     * Creates an instance of {@code EvidenceRecordRenewalDigestBuilder} allowing to build hash for
     * an evidence record's renewal, with a default SHA256 digest algorithm to be used on hash-tree
     * renewal computation (see note).
     * Builds digest for the last available ArchiveTimeStamp or ArchiveTimeStampChain, based on the called method.
     * NOTE: time-stamp renewal uses digest algorithm extracted from the last ArchiveTimeStampChain.
     *
     * @param evidenceRecord {@link DefaultEvidenceRecord}
     */
    protected AbstractEvidenceRecordRenewalDigestBuilder(final DefaultEvidenceRecord evidenceRecord) {
        this(evidenceRecord, DigestAlgorithm.SHA256);
    }

    /**
     * Creates an instance of {@code EvidenceRecordRenewalDigestBuilder} allowing to build hash for
     * an evidence record's renewal, with the provided {@code digestAlgorithm} (see note below).
     * Builds digest for the last available ArchiveTimeStamp or ArchiveTimeStampChain, based on the called method.
     * NOTE: time-stamp renewal uses digest algorithm extracted from the last ArchiveTimeStampChain.
     *
     * @param evidenceRecord {@link DefaultEvidenceRecord}
     * @param digestAlgorithm {@link DigestAlgorithm} to be used on hash-tree renewal hash computation
     */
    protected AbstractEvidenceRecordRenewalDigestBuilder(final DefaultEvidenceRecord evidenceRecord, final DigestAlgorithm digestAlgorithm) {
        Objects.requireNonNull(evidenceRecord, "EvidenceRecord cannot be null!");
        Objects.requireNonNull(digestAlgorithm, "DigestAlgorithm cannot be null!");
        this.evidenceRecord = evidenceRecord;
        this.digestAlgorithm = digestAlgorithm;
    }

    /**
     * Sets detached content to be used for a digest group hash computation on hash-tree renewal
     * NOTE : at least one of the documents from the original data group should be provided
     *        for a correct hash-tree renewal
     *
     * @param detachedContent a list of {@link DSSDocument} detached documents
     * @return this builder
     */
    public AbstractEvidenceRecordRenewalDigestBuilder setDetachedContent(List<DSSDocument> detachedContent) {
        this.detachedContent = detachedContent;
        return this;
    }

    /**
     * Gets an {@code ArchiveTimeStampObject} to build hash for.
     * Returns the set {@code archiveTimeStampObject} when valid, otherwise returns
     * the last {@code ArchiveTimeStampObject}
     *
     * @return {@link ArchiveTimeStampObject}
     */
    protected ArchiveTimeStampObject getLastArchiveTimeStampObject() {
        // return last ArchiveTimeStamp
        List<? extends ArchiveTimeStampChainObject> archiveTimeStampSequence = evidenceRecord.getArchiveTimeStampSequence();
        ArchiveTimeStampChainObject lastArchiveTimeStampChain = archiveTimeStampSequence.get(archiveTimeStampSequence.size() - 1);
        List<? extends ArchiveTimeStampObject> archiveTimeStamps = lastArchiveTimeStampChain.getArchiveTimeStamps();
        return archiveTimeStamps.get(archiveTimeStamps.size() - 1);
    }

    /**
     * Gets an {@code ArchiveTimeStampChainObject} to build hash for.
     * Returns the set {@code archiveTimeStampChainObject} when valid, otherwise returns
     * the last {@code ArchiveTimeStampChainObject}
     *
     * @return {@link ArchiveTimeStampChainObject}
     */
    protected ArchiveTimeStampChainObject getLastArchiveTimeStampChainObject() {
        // return last ArchiveTimeStampChain
        List<? extends ArchiveTimeStampChainObject> archiveTimeStampSequence = evidenceRecord.getArchiveTimeStampSequence();
        return archiveTimeStampSequence.get(archiveTimeStampSequence.size() - 1);
    }

    /**
     * Extracts a digest algorithm defined within XML {@code ArchiveTimeStampChainObject}
     *
     * @param archiveTimeStampChain {@link ArchiveTimeStampChainObject} to get digest algorithm from
     * @return {@link DigestAlgorithm}
     */
    protected DigestAlgorithm getDigestAlgorithm(ArchiveTimeStampChainObject archiveTimeStampChain) {
        return archiveTimeStampChain.getDigestAlgorithm();
    }

    @Override
    public abstract DSSMessageDigest buildTimeStampRenewalDigest();

}
