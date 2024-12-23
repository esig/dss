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
package eu.europa.esig.dss.token.digest;

import eu.europa.esig.dss.model.DSSException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.ByteBuffer;
import java.util.Objects;

/**
 * This class is used to encode given digest to its ASN.1 DigestInfo representation.
 * NOTE: This class is used on RSA signing.
 *
 */
public class DigestInfoEncoder {

    private static final Logger LOG = LoggerFactory.getLogger(DigestInfoEncoder.class);

    /**
     * Empty constructor
     */
    private DigestInfoEncoder() {
        // empty
    }

    /**
     * This method encodes the {@code algorithmOid} and {@code digest} combination into ASN.1 DigestInfo representation
     * {@code
     * DigestInfo ::= SEQUENCE {
     *    digestAlgorithm DigestAlgorithmIdentifier,
     *    digest Digest }
     * }
     *
     * @param algorithmOid {@link String} OID of the digest algorithm
     * @param digest the digest to be encoded
     * @return byte array containing a DER-encoded DigestInfo sequence
     */
    public static byte[] encode(final String algorithmOid, final byte[] digest) {
        Objects.requireNonNull(algorithmOid, "Digest algorithm OID cannot be null!");
        Objects.requireNonNull(digest, "Digest cannot be null!");

        try {
            // Convert OID string to byte array
            byte[] oidBytes = encodeOid(algorithmOid);

            // Length of the DigestInfo structure
            int oidLength = 2 + oidBytes.length; // OID tag + OID length
            int algorithmIdentifierLength = oidLength + 2; // OID tag + OID length
            int digestLength = 2 + digest.length; // OCTET STRING tag + Digest length
            int totalLength = 2 + algorithmIdentifierLength + 2 + digestLength; // SEQUENCE length + OID + Digest length

            // Buffer to hold the complete DigestInfo structure
            ByteBuffer buffer = ByteBuffer.allocate(totalLength);

            // Add SEQUENCE (0x30) tag and length
            buffer.put((byte) 0x30); // SEQUENCE tag
            buffer.put((byte) (totalLength - 2)); // Length of the sequence

            // Add AlgorithmIdentifier SEQUENCE (0x30) tag and length
            buffer.put((byte) 0x30); // SEQUENCE tag
            buffer.put((byte) algorithmIdentifierLength); // Length of the sequence

            // Add OID (0x06) tag and its length
            buffer.put((byte) 0x06); // OID tag
            buffer.put((byte) oidBytes.length); // OID length
            buffer.put(oidBytes); // OID value

            // Add DigestAlgorithm parameters (0x05) tag and length (null)
            buffer.put((byte) 0x05); // Null tag
            buffer.put((byte) 0x00); // Length for null (empty)

            // Add Digest (0x04) tag and length
            buffer.put((byte) 0x04); // OCTET STRING tag
            buffer.put((byte) digest.length); // Length of digest
            buffer.put(digest); // Digest value

            return buffer.array();

        } catch (Exception e) {
            throw new DSSException(String.format("An error occurred on DigestInfo encoding : %s", e.getMessage()), e);
        }
    }

    private static byte[] encodeOid(String oid) {
        String[] parts = oid.split("\\.");

        int byteLength = -1;
        for (String part : parts) {
            byteLength += getBytes(Integer.parseInt(part), 1);
        }

        byte[] encodedOid = new byte[byteLength];
        encodedOid[0] = (byte) (40 * Integer.parseInt(parts[0]) + Integer.parseInt(parts[1])); // First two OID numbers are combined

        int position = 1;
        for (int i = 2; i < parts.length; i++) {
            position += encodeOidPart(encodedOid, Integer.parseInt(parts[i]), position);
        }
        return encodedOid;
    }

    private static int getBytes(int value, int i) {
        if (value < 128) {
            return i;
        }
        return getBytes(value >> 7, ++i);
    }

    private static int encodeOidPart(byte[] encodedOid, int value, int position) {
        if (value < 128) {
            encodedOid[position] = (byte) value;
            return 1;
        } else {
            // Handle OID encoding where values >= 128 need multiple bytes
            int byteCount = (int) Math.ceil(Math.log(value) / Math.log(128));
            for (int i = byteCount - 1; i >= 0; i--) {
                int encodedByte = (byte) (value & 0x7F);
                value >>= 7;
                if (i < byteCount - 1) {
                    encodedByte |= (byte) 0x80; // Set the MSB to 1 for continuation bytes
                }
                encodeOidPart(encodedOid, encodedByte, position + i);
            }
            return byteCount;
        }
    }

    /**
     * This method verifies whether the {@code data} is ASN.1 DigestInfo encoded
     *
     * @param data byte array to verify
     * @return TRUE if the data is ASN.1 DigestInfo encoded, FALSE otherwise
     */
    public static boolean isEncoded(byte[] data) {
        try {
            if (data == null || data.length < 5) {
                // Minimum length check (SEQUENCE + AlgorithmIdentifier + Digest)
                return false;
            }

            int index = 0;

            // Check for SEQUENCE (0x30)
            if (data[index++] != 0x30) {
                return false;
            }

            // Get SEQUENCE length
            int seqLength = data[index++] & 0xFF;
            if (seqLength != data.length - 2) {
                // Ensure length matches the rest of the data
                return false;
            }

            // Check for AlgorithmIdentifier SEQUENCE (0x30)
            if (data[index++] != 0x30) {
                return false;
            }

            // Get AlgorithmIdentifier length
            int algorithmIdentifierLength = data[index++] & 0xFF;
            int algorithmIdentifierEnd = index + algorithmIdentifierLength;

            // Check for OID (0x06)
            if (data[index++] != 0x06) {
                return false;
            }

            // Get OID length
            int oidLength = data[index++] & 0xFF;
            if (index + oidLength > algorithmIdentifierEnd) {
                // Ensure OID length is valid
                return false;
            }
            index += oidLength; // Skip OID content

            // Check for NULL (optional, 0x05 followed by 0x00)
            if (index < algorithmIdentifierEnd) {
                if (data[index] == 0x05 && index + 1 < algorithmIdentifierEnd && data[index + 1] == 0x00) {
                    index += 2; // Skip NULL
                } else {
                    return false;
                }
            }

            // Ensure we are at the end of AlgorithmIdentifier
            if (index != algorithmIdentifierEnd) {
                return false;
            }

            // Check for Digest (OCTET STRING, 0x04)
            if (index >= data.length || data[index++] != 0x04) {
                return false;
            }

            // Get Digest length
            int digestLength = data[index++] & 0xFF;
            if (index + digestLength != data.length) {
                // Ensure Digest length matches the rest of the data
                return false;
            }

            // Everything checks out
            return true;

        } catch (Exception e) {
            LOG.debug("An error occurred on DigestInfo reading : {}", e.getMessage(), e);
            return false;
        }
    }

}
