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

import java.util.List;

/**
 * This class contains utility methods required for a processing and validation of an embedded evidence record
 *
 */
public interface EmbeddedEvidenceRecordHelper {

    /**
     * Gets a master signature, enveloping the current evidence record
     *
     * @return {@link AdvancedSignature}
     */
    AdvancedSignature getMasterSignature();

    /**
     * Gets the unsigned attribute property embedding the evidence record.
     * NOTE: can be null in case of a not yet embedded evidence record.
     *
     * @return {@link SignatureAttribute}
     */
    SignatureAttribute getEvidenceRecordAttribute();

    /**
     * Gets position of the evidence record carrying attribute within the signature
     * NOTE: can be null in case of a not yet embedded evidence record.
     *
     * @return {@link Integer}
     */
    Integer getOrderOfAttribute();

    /**
     * Gets position of the evidence record within its carrying attribute
     * NOTE: can be null in case of a not yet embedded evidence record.
     *
     * @return {@link Integer}
     */
    Integer getOrderWithinAttribute();

    /**
     * Gets a list of detached documents
     *
     * @return a list of {@link DSSDocument}s
     */
    List<DSSDocument> getDetachedContents();

    /**
     * Builds digest for the embedded evidence record for the given {@code DigestAlgorithm}.
     * This method uses an existing coding of a signature for hash generation.
     *
     * @param digestAlgorithm {@link DigestAlgorithm}
     * @return {@link Digest}
     */
    Digest getMasterSignatureDigest(DigestAlgorithm digestAlgorithm);

    /**
     * Builds digest for the embedded evidence record for the given {@code DigestAlgorithm} using a specified encoding.
     * The method can be called only for a CAdES signature implementation.
     * NOTE: please use the method {@code #isEncodingSelectionSupported} to check whether the encoding choice is
     *       supported by the current implementation.
     *       Use {@code #getMasterSignatureDigest(digestAlgorithm)} method otherwise.
     *
     * @param digestAlgorithm {@link DigestAlgorithm}
     * @param derEncoded whether the signature shall be DER-encoded
     * @return {@link Digest}
     */
    Digest getMasterSignatureDigest(DigestAlgorithm digestAlgorithm, boolean derEncoded);

    /**
     * Gets whether the selection of a target encoding is supported by the current implementation.
     * This method is used to resolve the interoperability issues between ETSI TS 119 122-3 and RFC 4998 embedded ERS,
     * requiring hash computation in different ways.
     *
     * @return TRUE if the encoding selection is supported by the current implementation, FALSE otherwise
     */
    boolean isEncodingSelectionSupported();

}
