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
package eu.europa.esig.dss.eaa.sd.jwt.creation;

import eu.europa.esig.dss.eaa.common.creation.claim.AttestationClaimArray;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Represents a JSON array to be incorporated as an SD-JWT VC claim
 *
 */
public class SDJWTClaimArray extends SDJWTClaim implements AttestationClaimArray<SDJWTClaim> {

    private static final long serialVersionUID = -8747676551662684772L;

    /** Decoy digests used to hide the number of selectively disclosable items */
    private final List<String> decoyDigests = new ArrayList<>();

    /**
     * Create a {@link SDJWTClaimArray}. The name of the claim will be null.
     *
     * @return the created {@link SDJWTClaimArray}
     */
    public static SDJWTClaimArray create() {
        return new SDJWTClaimArray(null, false, null);
    }

    /**
     * Create a {@link SDJWTClaimArray} with the provided name
     *
     * @param name {@link String} the name of the claim
     * @return the created {@link SDJWTClaimArray}
     */
    public static SDJWTClaimArray create(final String name) {
        return new SDJWTClaimArray(name, false, null);
    }

    /**
     * Create a selectively disclosable {@link SDJWTClaimArray}. The name of the claim will be null.
     *
     * @return the created {@link SDJWTClaimArray}
     */
    public static SDJWTClaimArray createSelectivelyDisclosable() {
        return new SDJWTClaimArray(null, true, null);
    }

    /**
     * Create a selectively disclosable {@link SDJWTClaimArray} with the provided salt. The name of the claim will be null.
     *
     * @param salt {@link String} the salt value
     * @return the created {@link SDJWTClaimArray}
     */
    public static SDJWTClaimArray createSelectivelyDisclosableWithSalt(final String salt) {
        return new SDJWTClaimArray(null, true, salt);
    }

    /**
     * Create a selectively disclosable {@link SDJWTClaimArray} with the provided name
     *
     * @param name {@link String} the name of the claim
     * @return the created {@link SDJWTClaimArray}
     */
    public static SDJWTClaimArray createSelectivelyDisclosable(final String name) {
        return new SDJWTClaimArray(name, true, null);
    }

    /**
     * Create a selectively disclosable {@link SDJWTClaimArray} with the provided name and salt
     *
     * @param name {@link String} the name of the claim
     * @param salt {@link String} the salt value
     * @return the created {@link SDJWTClaimArray}
     */
    public static SDJWTClaimArray createSelectivelyDisclosableWithSalt(final String name, final String salt) {
        return new SDJWTClaimArray(name, true, salt);
    }

    /**
     * Default constructor
     */
    protected SDJWTClaimArray() {
        this(null, false, null);
    }

    /**
     * Constructor with the claim name
     *
     * @param name {@link String} the claim name
     */
    protected SDJWTClaimArray(final String name) {
        this(name, false, null);
    }

    /**
     * Constructor with the claim name, selectively disclosable status and salt provided
     *
     * @param name  {@link String} the claim name
     * @param selectivelyDisclosable whether the claim is selectively disclosable
     * @param salt {@link String} the salt (mandatory if the claim is selectively disclosable)
     */
    protected SDJWTClaimArray(final String name, final boolean selectivelyDisclosable, final String salt) {
        super(name, new ArrayList<SDJWTClaim>(), selectivelyDisclosable, salt);
    }

    /**
     * Constructor with the claim name, value, selectively disclosable status and salt provided
     *
     * @param name  {@link String} the claim name
     * @param value {@link List} value
     * @param selectivelyDisclosable whether the claim is selectively disclosable
     * @param salt {@link String} the salt (mandatory if the claim is selectively disclosable)
     */
    protected SDJWTClaimArray(final String name, final List<?> value, final boolean selectivelyDisclosable, final String salt) {
        super(name, value, selectivelyDisclosable, salt);
    }

    @Override
    public void addElement(final SDJWTClaim element) {
        getElements().add(element);
    }

    @Override
    public List<SDJWTClaim> getElements() {
        return (List<SDJWTClaim>) getValue();
    }

    /**
     * Adds a decoy digest to the claim.
     *
     * @param digest the decoy digest to add
     */
    public void addDecoyDigest(String digest) {
        decoyDigests.add(digest);
    }

    /**
     * Gets the decoy digests of this claim
     *
     * @return The list of decoy digests
     */
    public List<String> getDecoyDigests() {
        return Collections.unmodifiableList(decoyDigests);
    }
}
