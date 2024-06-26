/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * 
 * This file is part of the "DSS - Digital Signature Services" project.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.evidencerecord.asn1.digest;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.evidencerecord.common.digest.AbstractDataObjectDigestBuilder;
import eu.europa.esig.dss.model.DSSDocument;

import java.io.InputStream;

/**
 * Generates digests for data objects to be protected by an IETF RFC 4998 ERS evidence-record
 *
 */
public class ASN1EvidenceRecordDataObjectDigestBuilder extends AbstractDataObjectDigestBuilder {

    /**
     * Constructor to create a builder for computing digest on the given binaries using a SHA-256 digest algorithm
     *
     * @param binaries byte array to compute hash on
     */
    public ASN1EvidenceRecordDataObjectDigestBuilder(final byte[] binaries) {
        super(binaries);
    }

    /**
     * Constructor to create a builder for computing digest on the given InputStream using a SHA-256 digest algorithm
     *
     * @param inputStream {@link InputStream} to compute hash on
     */
    public ASN1EvidenceRecordDataObjectDigestBuilder(final InputStream inputStream) {
        super(inputStream);
    }

    /**
     * Constructor to create a builder for computing digest on the given document using a SHA-256 digest algorithm
     *
     * @param document {@link DSSDocument} to compute hash on
     */
    public ASN1EvidenceRecordDataObjectDigestBuilder(final DSSDocument document) {
        super(document);
    }

    /**
     * Constructor to create a builder for computing digest on the given binaries using a provided digest algorithm
     *
     * @param binaries byte array to compute hash on
     * @param digestAlgorithm {@link DigestAlgorithm} to be used on hash computation
     */
    public ASN1EvidenceRecordDataObjectDigestBuilder(final byte[] binaries, final DigestAlgorithm digestAlgorithm) {
        super(binaries, digestAlgorithm);
    }

    /**
     * Constructor to create a builder for computing digest on the given InputStream using a provided digest algorithm
     *
     * @param inputStream {@link InputStream} to compute hash on
     * @param digestAlgorithm {@link DigestAlgorithm} to be used on hash computation
     */
    public ASN1EvidenceRecordDataObjectDigestBuilder(final InputStream inputStream, final DigestAlgorithm digestAlgorithm) {
        super(inputStream, digestAlgorithm);
    }

    /**
     * Constructor to create a builder for computing digest on the given document using a provided digest algorithm
     *
     * @param document {@link DSSDocument} to compute hash on
     * @param digestAlgorithm {@link DigestAlgorithm} to be used on hash computation
     */
    public ASN1EvidenceRecordDataObjectDigestBuilder(final DSSDocument document, final DigestAlgorithm digestAlgorithm) {
        super(document, digestAlgorithm);
    }

}
