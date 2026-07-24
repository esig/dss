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
package eu.europa.esig.dss.attestation.revocation.validation.statuslist;

import eu.europa.esig.dss.attestation.revocation.model.statuslist.TokenStatusList;
import eu.europa.esig.dss.attestation.revocation.model.statuslist.StatusListPayload;
import eu.europa.esig.dss.enumerations.AttestationStatus;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.spi.attestation.AttestationRevocationToken;
import eu.europa.esig.dss.spi.attestation.AttestationRevocationTokenBinary;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.utils.Utils;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Objects;
import java.util.zip.InflaterInputStream;

/**
 * Contains common methods and logic for validation of a Token Status List
 *
 */
public abstract class AbstractTokenStatusListValidator implements TokenStatusListValidator {

    /** Binaries of the retrieved revocation list */
    protected byte[] statusListDocument;

    /** Cached instance of a signature used to sign the token */
    private AdvancedSignature tokenSignature;

    /**
     * Empty constructor
     */
    protected AbstractTokenStatusListValidator() {
        // empty
    }

    /**
     * Constructor with the revocation list
     *
     * @param statusListDocument byte array of the revocation list document
     */
    protected AbstractTokenStatusListValidator(final byte[] statusListDocument) {
        this.statusListDocument = statusListDocument;
    }

    @Override
    public AttestationRevocationToken getRevocationToken(int index) {
        Objects.requireNonNull(statusListDocument, "Token Status List Document cannot be null!");

        /*
         * 8.2. Status List Response
         *
         * The body of such an HTTP response contains the raw Status List Token,
         * that means the binary encoding as defined in Section 9.2.1 of [RFC8392] for
         * a Status List Token in CWT format and the JWS Compact Serialization form for
         * a Status List Token in JWT format.
         */
        AdvancedSignature signature = getTokenSignature();
        if (signature != null) {
            StatusListPayload statusListPayload = getPayload(signature);
            return TokenStatusList.initBuilder()
                    .setBinary(new AttestationRevocationTokenBinary(statusListDocument))
                    .setSignature(signature)
                    .setPayload(statusListPayload)
                    .setStatus(getEAAStatus(statusListPayload, index))
                    .build();
        }
        return null;
    }

    /**
     * Gets the token signature. If already built, returns the cached value.
     *
     * @return {@link AdvancedSignature}
     */
    protected AdvancedSignature getTokenSignature() {
        if (tokenSignature == null) {
            tokenSignature = buildTokenSignature();
        }
        return tokenSignature;
    }

    /**
     * Builds a signature of the token
     *
     * @return {@link AdvancedSignature}
     */
    protected abstract AdvancedSignature buildTokenSignature();

    /**
     * Gets the representation of a Token Status List Payload signed by the {@code signature}
     *
     * @param signature {@link AdvancedSignature}
     * @return {@link StatusListPayload}
     */
    protected abstract StatusListPayload getPayload(AdvancedSignature signature);

    /**
     * Gets the EAA Status for the given {@code attestation} based on the information retrieved from {@code statusListPayload}
     *
     * @param statusListPayload {@link StatusListPayload} of the retrieved token
     * @param index position of the revocation of the token in question
     * @return {@link AttestationStatus}
     */
    protected AttestationStatus getEAAStatus(StatusListPayload statusListPayload, int index) {
        byte[] statusListEncoded = statusListPayload.getStatusListEncoded();
        byte[] statusListDecompressed = decompressStatusList(statusListEncoded);

        Number statusListBits = statusListPayload.getStatusListBits();
        if (statusListBits == null) {
            throw new DSSException("The 'bits' claim of the Token Status List is not present or null!");
        }

        return getStatus(statusListDecompressed, index, statusListBits.intValue());
    }

    /**
     * Decompresses the Status List with a decompressor that is compatible with DEFLATE (RFC1951) and ZLIB (RFC1950)
     *
     * @param statusListArray byte array containing the original revocation list
     * @return byte array containing the decompressed revocation list
     */
    protected byte[] decompressStatusList(byte[] statusListArray) {
        try (ByteArrayInputStream bais = new ByteArrayInputStream(statusListArray);
             InflaterInputStream inflater = new InflaterInputStream(bais);
             ByteArrayOutputStream baos = new ByteArrayOutputStream()) {

            Utils.copy(inflater, baos);
            return baos.toByteArray();

        } catch (IOException e) {
            throw new DSSException(String.format(
                    "An error occurred during on attempt to decompress the Token Status List : %s", e.getMessage()), e);
        }
    }

    /**
     * Retrieves the revocation value of the index specified in the Referenced Token.
     *
     * @param decompressed decompressed revocation list byte array
     * @param index position of the revocation of the token in question
     * @param bits number of bits per revocation
     * @return {@link AttestationStatus}
     */
    protected AttestationStatus getStatus(byte[] decompressed, int index, int bits) {
        if (!(bits == 1 || bits == 2 || bits == 4 || bits == 8)) {
            throw new DSSException(String.format("'bits' must be 1, 2, 4 or 8. Obtained value '%s'", bits));
        }

        int statusesPerByte = 8 / bits;
        int byteIndex = index / statusesPerByte;

        if (byteIndex >= decompressed.length) {
            throw new DSSException(String.format("The position of the index '%s' is out of bounds of " +
                    "the obtained revocation list array with size '%s' bytes (%s bits)!", index, decompressed.length, decompressed.length * 8));
        }

        int positionInByte = index % statusesPerByte;

        int shift = positionInByte * bits;

        int mask = (1 << bits) - 1;

        int value = decompressed[byteIndex] & 0xFF;

        int statusValue = (value >> shift) & mask;
        return AttestationStatus.forBitValue(statusValue);
    }

}
