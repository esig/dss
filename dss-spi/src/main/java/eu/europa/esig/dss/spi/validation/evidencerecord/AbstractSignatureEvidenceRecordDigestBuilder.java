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
package eu.europa.esig.dss.spi.validation.evidencerecord;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.spi.validation.SignatureAttribute;

import java.util.Objects;

/**
 * Abstract implementation of the {@code SignatureEvidenceRecordDigestGenerator}
 *
 */
public abstract class AbstractSignatureEvidenceRecordDigestBuilder implements SignatureEvidenceRecordDigestBuilder {

    /**
     * Signature document to compute hash value for
     */
    protected final DSSDocument signatureDocument;

    /**
     * The digest algorithm to be used on hash computation.
     * Default : DigestAlgorithm.SHA256
     */
    protected final DigestAlgorithm digestAlgorithm;

    /**
     * The signature incorporating the evidence record
     */
    protected final AdvancedSignature signature;

    /**
     * Attribute containing an evidence record to compute digest for
     */
    protected final SignatureAttribute evidenceRecordAttribute;

    /**
     * Defines whether the new evidence-record shall be added to the last available evidence-record attribute,
     * when present. Otherwise, the hash will be computed based on the whole document content (default behavior).
     */
    protected boolean parallelEvidenceRecord;

    /**
     * Default constructor to instantiate builder with a SHA-256 digest algorithm
     *
     * @param signatureDocument {@link DSSDocument} to compute message-imprint for
     */
    protected AbstractSignatureEvidenceRecordDigestBuilder(final DSSDocument signatureDocument) {
        this(signatureDocument, DigestAlgorithm.SHA256);
    }

    /**
     * Constructor to instantiate builder with a custom digest algorithm
     *
     * @param signatureDocument {@link DSSDocument} to compute message-imprint for
     * @param digestAlgorithm {@link DigestAlgorithm} to be used
     */
    protected AbstractSignatureEvidenceRecordDigestBuilder(final DSSDocument signatureDocument, final DigestAlgorithm digestAlgorithm) {
        Objects.requireNonNull(signatureDocument, "Signature document cannot be null!");
        Objects.requireNonNull(digestAlgorithm, "DigestAlgorithm cannot be null!");
        this.signatureDocument = signatureDocument;
        this.digestAlgorithm = digestAlgorithm;
        this.signature = null;
        this.evidenceRecordAttribute = null;
    }

    /**
     * Constructor to instantiate builder from a {@code signature} for the given {@code evidenceRecordAttribute}
     *
     * @param signature {@link AdvancedSignature} containing the incorporated evidence record
     * @param evidenceRecordAttribute {@link SignatureAttribute} location of the evidence record
     * @param digestAlgorithm {@link DigestAlgorithm} to be used
     */
    protected AbstractSignatureEvidenceRecordDigestBuilder(final AdvancedSignature signature, final SignatureAttribute evidenceRecordAttribute,
                                                           final DigestAlgorithm digestAlgorithm) {
        Objects.requireNonNull(signature, "Signature cannot be null!");
        Objects.requireNonNull(digestAlgorithm, "DigestAlgorithm cannot be null!");
        this.signature = signature;
        this.evidenceRecordAttribute = evidenceRecordAttribute;
        this.digestAlgorithm = digestAlgorithm;
        this.signatureDocument = null;
    }

    /**
     * Sets whether the message-imprint for an evidence record shall be computed as for a parallel evidence-record
     * (i.e. to be incorporated within the latest evidence-record attribute, when available). Otherwise, will compute
     * message-imprint based on the whole signature's content, including coverage of other existing evidence-record.
     * Default : FALSE (computes digest based on the whole signature's content)
     *
     * @param parallelEvidenceRecord whether the message-imprint for an evidence record shall be computed as for a parallel evidence-record
     * @return this builder
     */
    public AbstractSignatureEvidenceRecordDigestBuilder setParallelEvidenceRecord(boolean parallelEvidenceRecord) {
        this.parallelEvidenceRecord = parallelEvidenceRecord;
        return this;
    }

    /**
     * Returns digest of the given document
     *
     * @param document {@link DSSDocument} to compute digest for
     * @return {@link Digest}
     */
    protected Digest getDigest(DSSDocument document) {
        return new Digest(digestAlgorithm, document.getDigestValue(digestAlgorithm));
    }

}
