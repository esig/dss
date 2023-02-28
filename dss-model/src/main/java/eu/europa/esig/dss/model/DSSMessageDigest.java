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
package eu.europa.esig.dss.model;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;

/**
 * This class contains a digest algorithm and a digest value for message-digest computation.
 *
 */
public class DSSMessageDigest extends Digest {

    private static final long serialVersionUID = 8294786241127932403L;

    /**
     * Empty constructor to instantiate message-digest
     */
    public DSSMessageDigest() {
        super();
    }

    /**
     * Default constructor with provided digest algorithm and the corresponding hash value
     *
     * @param algorithm {@link DigestAlgorithm} used algorithm
     * @param value byte array digest
     */
    public DSSMessageDigest(DigestAlgorithm algorithm, byte[] value) {
        super(algorithm, value);
    }

    /**
     * Constructor with provided {@code Digest} object
     *
     * @param digest {@link Digest}
     */
    public DSSMessageDigest(Digest digest) {
        this(digest.getAlgorithm(), digest.getValue());
    }

    /**
     * Creates empty message-digest object
     *
     * @return {@link DSSMessageDigest} with empty values
     */
    public static DSSMessageDigest createEmptyDigest() {
        return new DSSMessageDigest();
    }

    /**
     * Checks whether the object contains a value
     *
     * @return TRUE if the object is empty, FALSE otherwise
     */
    public boolean isEmpty() {
        return getAlgorithm() == null || getValue() == null;
    }

    @Override
    public String toString() {
        return "MessageDigest [" + super.toString() + "]";
    }

}
