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
package eu.europa.esig.dss.attestation.sd.jwt.creation;

import eu.europa.esig.dss.attestation.common.creation.claim.AbstractAttestationClaim;

/**
 * Implementation of an EAA SD-JWT Claim
 */
public class SDJWTClaim extends AbstractAttestationClaim {

    private static final long serialVersionUID = 4900197826207151947L;

    /** Identifies whether the claim is selectively disclosable */
    private final boolean selectivelyDisclosable;

    /** Salt of the selectively disclosable claim, when applicable */
    private final String salt;

    /**
     * Create a {@link SDJWTClaim} with the provided value. The name of the claim will be null.
     *
     * @param value {@link Object} the value of the claim
     * @return the created {@link SDJWTClaim}
     */
    public static SDJWTClaim create(final Object value) {
        return new SDJWTClaim(null, value, false);
    }

    /**
     * Create a {@link SDJWTClaim} with the provided name and value.
     *
     * @param name {@link String} the claim name
     * @param value {@link Object} the claim value
     * @return the created {@link SDJWTClaim}
     */
    public static SDJWTClaim create(final String name, final Object value) {
        return new SDJWTClaim(name, value, false);
    }

    /**
     * Create a selectively disclosable {@link SDJWTClaim} with the provided value. The name of the claim will be null.
     * The salt will be generated during the EAA Payload computation.
     *
     * @param value {@link Object} the value of the claim
     * @return the created {@link SDJWTClaim}
     */
    public static SDJWTClaim createSelectivelyDisclosable(final Object value) {
        return new SDJWTClaim(null, value, true);
    }

    /**
     * Create a selectively disclosable {@link SDJWTClaim} with the provided value and salt
     *
     * @param value {@link Object} the value of the claim
     * @param salt {@link String} the salt
     * @return the created {@link SDJWTClaim}
     */
    public static SDJWTClaim createSelectivelyDisclosableWithSalt(final Object value, final String salt) {
        return new SDJWTClaim(null, value, true, salt);
    }

    /**
     * Create a selectively disclosable {@link SDJWTClaim} with the provided name and value.
     * The salt will be generated during the EAA Payload computation.
     *
     * @param name {@link String} the claim name
     * @param value {@link Object} the value of the claim
     * @return the created {@link SDJWTClaim}
     */
    public static SDJWTClaim createSelectivelyDisclosable(final String name, final Object value) {
        return new SDJWTClaim(name, value, true);
    }

    /**
     * Create a selectively disclosable {@link SDJWTClaim} with the provided name, value and salt
     *
     * @param name {@link String} the claim name
     * @param value {@link Object} the value of the claim
     * @param salt {@link String} the salt
     * @return the created {@link SDJWTClaim}
     */
    public static SDJWTClaim createSelectivelyDisclosableWithSalt(final String name, final Object value, final String salt) {
        return new SDJWTClaim(name, value, true, salt);
    }

    /**
     * Create a {@link SDJWTClaimObject}. The name of the claim will be null.
     *
     * @return the created {@link SDJWTClaimObject}
     */
    public static SDJWTClaimObject createObject() {
        return SDJWTClaimObject.create();
    }

    /**
     * Create a {@link SDJWTClaimObject} with the provided name.
     *
     * @param name {@link String} the name of the claim
     * @return the created {@link SDJWTClaimObject}
     */
    public static SDJWTClaimObject createObject(final String name) {
        return SDJWTClaimObject.create(name);
    }

    /**
     * Create a selectively disclosable {@link SDJWTClaimObject}. The name of the claim will be null.
     *
     * @return the created {@link SDJWTClaimObject}
     */
    public static SDJWTClaimObject createObjectSelectivelyDisclosable() {
        return SDJWTClaimObject.createSelectivelyDisclosable();
    }

    /**
     * Create a selectively disclosable {@link SDJWTClaimObject} with the provided salt. The name of the claim will be null.
     *
     * @param salt {@link String} the salt value
     * @return the created {@link SDJWTClaimObject}
     */
    public static SDJWTClaimObject createObjectSelectivelyDisclosableWithSalt(final String salt) {
        return SDJWTClaimObject.createSelectivelyDisclosableWithSalt(salt);
    }

    /**
     * Create a selectively disclosable {@link SDJWTClaimObject} with the provided name.
     *
     * @param name {@link String} the name of the claim
     * @return the created {@link SDJWTClaimObject}
     */
    public static SDJWTClaimObject createObjectSelectivelyDisclosable(final String name) {
        return SDJWTClaimObject.createSelectivelyDisclosable(name);
    }

    /**
     * Create a selectively disclosable {@link SDJWTClaimObject} with the provided name and salt.
     *
     * @param name {@link String} the name of the claim
     * @param salt {@link String} the salt value
     * @return the created {@link SDJWTClaimObject}
     */
    public static SDJWTClaimObject createObjectSelectivelyDisclosableWithSalt(final String name, final String salt) {
        return SDJWTClaimObject.createSelectivelyDisclosableWithSalt(name, salt);
    }

    /**
     * Create a {@link SDJWTClaimArray}. The name of the claim will be null.
     *
     * @return the created {@link SDJWTClaimArray}
     */
    public static SDJWTClaimArray createArray() {
        return SDJWTClaimArray.create();
    }

    /**
     * Create a {@link SDJWTClaimArray} with the provided name.
     *
     * @param name {@link String} the name of the claim
     * @return the created {@link SDJWTClaimArray}
     */
    public static SDJWTClaimArray createArray(final String name) {
        return SDJWTClaimArray.create(name);
    }

    /**
     * Create a selectively disclosable {@link SDJWTClaimArray}. The name of the claim will be null.
     *
     * @return the created {@link SDJWTClaimArray}
     */
    public static SDJWTClaimArray createArraySelectivelyDisclosable() {
        return SDJWTClaimArray.createSelectivelyDisclosable();
    }

    /**
     * Create a selectively disclosable {@link SDJWTClaimArray} with the provided salt. The name of the claim will be null.
     *
     * @param salt {@link String} the salt value
     * @return the created {@link SDJWTClaimArray}
     */
    public static SDJWTClaimArray createArraySelectivelyDisclosableWithSalt(final String salt) {
        return SDJWTClaimArray.createSelectivelyDisclosableWithSalt(salt);
    }

    /**
     * Create a selectively disclosable {@link SDJWTClaimArray} with the provided name.
     *
     * @param name {@link String} the name of the claim
     * @return the created {@link SDJWTClaimArray}
     */
    public static SDJWTClaimArray createArraySelectivelyDisclosable(final String name) {
        return SDJWTClaimArray.createSelectivelyDisclosable(name);
    }

    /**
     * Create a selectively disclosable {@link SDJWTClaimArray} with the provided name and salt.
     *
     * @param name {@link String} the name of the claim
     * @param salt {@link String} the salt value
     * @return the created {@link SDJWTClaimArray}
     */
    public static SDJWTClaimArray createArraySelectivelyDisclosableWithSalt(final String name, final String salt) {
        return SDJWTClaimArray.createSelectivelyDisclosableWithSalt(name, salt);
    }

    /**
     * Constructor with the claim name, value, selectively disclosable revocation.
     * When the selectivelyDisclosable revocation is enabled but no salt is provided,
     * the salt will be generated during the EAA Payload computation.
     *
     * @param name {@link String} the claim name
     * @param value {@link Object} the value of the claim
     * @param selectivelyDisclosable whether the claim is selectively disclosable
     */
    protected SDJWTClaim(final String name, final Object value, final boolean selectivelyDisclosable) {
        this(name, value, selectivelyDisclosable, null);
    }

    /**
     * Constructor with the claim name, value, selectively disclosable revocation and salt provided
     *
     * @param name {@link String} the claim name
     * @param value {@link Object} the value of the claim
     * @param selectivelyDisclosable whether the claim is selectively disclosable
     * @param salt {@link String} the salt (mandatory if the claim is selectively disclosable)
     */
    protected SDJWTClaim(final String name, final Object value, final boolean selectivelyDisclosable, final String salt) {
        super(name, value);
        this.selectivelyDisclosable = selectivelyDisclosable;
        this.salt = salt;
    }

    /**
     * Gets whether this claim is selectively disclosable
     *
     * @return whether the claim is disclosable
     */
    public boolean isSelectivelyDisclosable() {
        return selectivelyDisclosable;
    }

    /**
     * Gets the salt
     *
     * @return {@link String}
     */
    public String getSalt() {
        return salt;
    }

    @Override
    public String toString() {
        return "SDJWTEAAClaim [" +
                "name='" + getName() + '\'' +
                ", value=" + getValue() +
                ", selectivelyDisclosable=" + selectivelyDisclosable +
                ", salt='" + salt + '\'' +
                "]";
    }

}
