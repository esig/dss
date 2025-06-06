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
package eu.europa.esig.dss.model.policy;

import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;

import java.io.Serializable;
import java.util.Objects;

/**
 * DTO containing a pair of an {@code eu.europa.esig.dss.enumerations.EncryptionAlgorithm} and
 * its corresponding minimal allowed key size
 *
 */
public class EncryptionAlgorithmWithMinKeySize implements Serializable {

    private static final long serialVersionUID = -311662580001422950L;

    /** The Encryption algorithm */
    private final EncryptionAlgorithm encryptionAlgorithm;

    /** The minimal accepted key size */
    private final int minKeySize;

    /**
     * Default constructor
     *
     * @param encryptionAlgorithm {@link EncryptionAlgorithm}
     * @param minKeySize integer key size. 0 when not defined
     */
    public EncryptionAlgorithmWithMinKeySize(final EncryptionAlgorithm encryptionAlgorithm, int minKeySize) {
        this.encryptionAlgorithm = encryptionAlgorithm;
        this.minKeySize = minKeySize;
    }

    /**
     * Gets Encryption algorithm
     *
     * @return {@link EncryptionAlgorithm}
     */
    public EncryptionAlgorithm getEncryptionAlgorithm() {
        return encryptionAlgorithm;
    }

    /**
     * Gets the minimum key size value
     *
     * @return key size
     */
    public int getMinKeySize() {
        return minKeySize;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        EncryptionAlgorithmWithMinKeySize that = (EncryptionAlgorithmWithMinKeySize) o;
        return minKeySize == that.minKeySize
                && encryptionAlgorithm == that.encryptionAlgorithm;
    }

    @Override
    public int hashCode() {
        int result = Objects.hashCode(encryptionAlgorithm);
        result = 31 * result + minKeySize;
        return result;
    }

    @Override
    public String toString() {
        return "EncryptionAlgorithmWithMinKeySize [" +
                "encryptionAlgorithm=" + encryptionAlgorithm +
                ", minKeySize=" + minKeySize +
                ']';
    }

}
