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
package eu.europa.esig.dss.enumerations;

/**
 * Represents a status of an attestation
 *
 */
public enum AttestationStatus {

    /**
     * The status of the Referenced Token is valid, correct or legal.
     */
    VALID(0x00),

    /**
     * The status of the Referenced Token is revoked, annulled, taken back, recalled or cancelled.
     */
    INVALID(0x01),

    /**
     * The status of the Referenced Token is temporarily invalid, hanging, debarred from privilege. This status is usually temporary.
     */
    SUSPENDED(0x02),

    /**
     * The status of the Referenced Token is application specific.
     */
    APPLICATION_SPECIFIC(0x03),

    /**
     * The EAA status is not known
     */
    UNKNOWN();

    /**
     * The bit representation of the Status Type in a byte hex representation.
     * Valid Status Type values range from 0x00-0xFF. Values are filled up with zeros if they have less than 8 bits.
     */
    private final Integer bitValue;

    /**
     * Empty constructor
     */
    AttestationStatus() {
        this.bitValue = null;
    }

    /**
     * Constructor with a value
     *
     * @param bitValue bit representation of the Status Type
     */
    AttestationStatus(final int bitValue) {
        this.bitValue = bitValue;
    }

    /**
     * Checks if the EAA status is valid
     *
     * @return TRUE if the EAA status is valid, FALSE otherwise
     */
    public boolean isValid() {
        return VALID == this;
    }

    /**
     * Gets the bit representation of the Status Type in a byte hex representation.
     *
     * @return status type int value
     */
    public Integer getBitValue() {
        return bitValue;
    }

    /**
     * Gets a corresponding {@code EAAStatusValue} type for the given {@code bitValue}
     *
     * @param bitValue the bit representation of the Status Type in a byte hex representation
     * @return {@link AttestationStatus}
     */
    public static AttestationStatus forBitValue(int bitValue) {
        for (AttestationStatus attestationStatus : values()) {
            if (bitValue == attestationStatus.bitValue) {
                return attestationStatus;
            }
        }
        return UNKNOWN;
    }

}
