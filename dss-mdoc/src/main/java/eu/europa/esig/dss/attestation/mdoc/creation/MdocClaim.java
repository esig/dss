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
package eu.europa.esig.dss.attestation.mdoc.creation;

import eu.europa.esig.dss.cbades.cbor.CBORObject;
import eu.europa.esig.dss.cbades.cbor.CBORObjectFactory;
import eu.europa.esig.dss.attestation.common.creation.claim.AbstractAttestationClaim;

import java.util.Arrays;

/**
 * Represents an ISO/IEC 18013-5 implementation of a selectively disclosable claim
 *
 */
public class MdocClaim extends AbstractAttestationClaim {

    private static final long serialVersionUID = -3226410210721510170L;

    /** Namespace of the element claim */
    private final String namespace;

    /** Integer identifier of the claim digest */
    private Integer digestId;

    /** Salt of the selectively disclosable claim, when applicable */
    private byte[] salt;

    /**
     * Create an {@link MdocClaim} to be used as an array item.
     *
     * @param value {@link Object} the claim value
     * @return the created {@link MdocClaim}
     */
    public static MdocClaim create(final Object value) {
        return new MdocClaim(value);
    }

    /**
     * Create an {@link MdocClaim} to be used as an object item.
     *
     * @param name {@link String} the claim name
     * @param value {@link Object} the claim value
     * @return the created {@link MdocClaim}
     */
    public static MdocClaim create(final String name, final Object value) {
        return new MdocClaim(name, value);
    }

    /**
     * Create a {@link MdocClaim} with the provided namespace, name and value.
     * NOTE: digestId and salt will be computed during attestation payload computation.
     *
     * @param namespace {@link String} the claim namespace
     * @param name {@link String} the claim name
     * @param value {@link Object} the claim value
     * @return the created {@link MdocClaim}
     */
    public static MdocClaim create(final String namespace, final String name, final Object value) {
        return new MdocClaim(namespace, name, value);
    }

    /**
     * Create a {@link MdocClaim} with the provided namespace, digestId, name and value.
     * NOTE: salt will be computed during attestation payload computation.
     *
     * @param namespace {@link String} the claim namespace
     * @param digestId integer representing a unique identifier of the claim within the namespace in attestation
     * @param name {@link String} the claim name
     * @param value {@link Object} the claim value
     * @return the created {@link MdocClaim}
     */
    public static MdocClaim create(final String namespace, final int digestId, final String name, final Object value) {
        return new MdocClaim(namespace, digestId, name, value);
    }

    /**
     * Create a {@link MdocClaim} with the provided namespace, name, value and salt.
     * NOTE: digestId will be computed during attestation payload computation.
     *
     * @param namespace {@link String} the claim namespace
     * @param name {@link String} the claim name
     * @param value {@link Object} the claim value
     * @param salt byte array containing a high entropy value to prevent a hash collision
     * @return the created {@link MdocClaim}
     */
    public static MdocClaim create(final String namespace, final String name, final Object value, final byte[] salt) {
        return new MdocClaim(namespace, name, value, salt);
    }

    /**
     * Create a {@link MdocClaim} with the provided namespace, digestId, name, value and salt.
     *
     * @param namespace {@link String} the claim namespace
     * @param digestId integer representing a unique identifier of the claim within the namespace in attestation
     * @param name {@link String} the claim name
     * @param value {@link Object} the claim value
     * @param salt byte array containing a high entropy value to prevent a hash collision
     * @return the created {@link MdocClaim}
     */
    public static MdocClaim create(final String namespace, final int digestId, final String name, final Object value, final byte[] salt) {
        return new MdocClaim(namespace, digestId, name, value, salt);
    }

    /**
     * Create an {@link MdocClaimObject} to be used as an array item.
     *
     * @return the created {@link MdocClaimObject}
     */
    public static MdocClaimObject createObject() {
        return MdocClaimObject.create();
    }

    /**
     * Create an {@link MdocClaimObject} to be used as an object item.
     *
     * @param name {@link String} the claim name
     * @return the created {@link MdocClaimObject}
     */
    public static MdocClaimObject createObject(final String name) {
        return MdocClaimObject.create(name);
    }

    /**
     * Create a {@link MdocClaimObject} with the provided namespace, name and value.
     * NOTE: digestId and salt will be computed during attestation payload computation.
     *
     * @param namespace {@link String} the claim namespace
     * @param name {@link String} the claim name
     * @return the created {@link MdocClaimObject}
     */
    public static MdocClaimObject createObject(final String namespace, final String name) {
        return MdocClaimObject.create(namespace, name);
    }

    /**
     * Create a {@link MdocClaimObject} with the provided namespace, digestId, name and value.
     * NOTE: salt will be computed during attestation payload computation.
     *
     * @param namespace {@link String} the claim namespace
     * @param digestId integer representing a unique identifier of the claim within the namespace in attestation
     * @param name {@link String} the claim name
     * @return the created {@link MdocClaimObject}
     */
    public static MdocClaimObject createObject(final String namespace, final int digestId, final String name) {
        return MdocClaimObject.create(namespace, digestId, name);
    }

    /**
     * Create a {@link MdocClaimObject} with the provided namespace, name, value and salt.
     * NOTE: digestId will be computed during attestation payload computation.
     *
     * @param namespace {@link String} the claim namespace
     * @param name {@link String} the claim name
     * @param salt byte array containing a high entropy value to prevent a hash collision
     * @return the created {@link MdocClaimObject}
     */
    public static MdocClaimObject createObject(final String namespace, final String name, final byte[] salt) {
        return MdocClaimObject.create(namespace, name, salt);
    }

    /**
     * Create a {@link MdocClaimObject} with the provided namespace, digestId, name, value and salt.
     *
     * @param namespace {@link String} the claim namespace
     * @param digestId integer representing a unique identifier of the claim within the namespace in attestation
     * @param name {@link String} the claim name
     * @param salt byte array containing a high entropy value to prevent a hash collision
     * @return the created {@link MdocClaimObject}
     */
    public static MdocClaimObject createObject(final String namespace, final int digestId, final String name, final byte[] salt) {
        return MdocClaimObject.create(namespace, digestId, name, salt);
    }

    /**
     * Create an {@link MdocClaimArray} to be used as an array item.
     *
     * @return the created {@link MdocClaimArray}
     */
    public static MdocClaimArray createArray() {
        return MdocClaimArray.create();
    }

    /**
     * Create an {@link MdocClaimArray} to be used as an object item.
     *
     * @param name {@link String} the claim name
     * @return the created {@link MdocClaimArray}
     */
    public static MdocClaimArray createArray(final String name) {
        return MdocClaimArray.create(name);
    }

    /**
     * Create a {@link MdocClaimArray} with the provided namespace, name and value.
     * NOTE: digestId and salt will be computed during attestation payload computation.
     *
     * @param namespace {@link String} the claim namespace
     * @param name {@link String} the claim name
     * @return the created {@link MdocClaimArray}
     */
    public static MdocClaimArray createArray(final String namespace, final String name) {
        return MdocClaimArray.create(namespace, name);
    }

    /**
     * Create a {@link MdocClaimArray} with the provided namespace, digestId, name and value.
     * NOTE: salt will be computed during attestation payload computation.
     *
     * @param namespace {@link String} the claim namespace
     * @param digestId integer representing a unique identifier of the claim within the namespace in attestation
     * @param name {@link String} the claim name
     * @return the created {@link MdocClaimArray}
     */
    public static MdocClaimArray createArray(final String namespace, final int digestId, final String name) {
        return MdocClaimArray.create(namespace, digestId, name);
    }

    /**
     * Create a {@link MdocClaimArray} with the provided namespace, name, value and salt.
     * NOTE: digestId will be computed during attestation payload computation.
     *
     * @param namespace {@link String} the claim namespace
     * @param name {@link String} the claim name
     * @param salt byte array containing a high entropy value to prevent a hash collision
     * @return the created {@link MdocClaimArray}
     */
    public static MdocClaimArray createArray(final String namespace, final String name, final byte[] salt) {
        return MdocClaimArray.create(namespace, name, salt);
    }

    /**
     * Create a {@link MdocClaimArray} with the provided namespace, digestId, name, value and salt.
     *
     * @param namespace {@link String} the claim namespace
     * @param digestId integer representing a unique identifier of the claim within the namespace in attestation
     * @param name {@link String} the claim name
     * @param salt byte array containing a high entropy value to prevent a hash collision
     * @return the created {@link MdocClaimArray}
     */
    public static MdocClaimArray createArray(final String namespace, final int digestId, final String name, final byte[] salt) {
        return MdocClaimArray.create(namespace, digestId, name, salt);
    }

    /**
     * Constructor with the value
     *
     * @param value {@link Object} the value of the claim
     */
    protected MdocClaim(Object value) {
        this(null, value);
    }

    /**
     * Constructor with the value
     *
     * @param name {@link String} key of the claim
     * @param value {@link Object} the value of the claim
     */
    protected MdocClaim(String name, Object value) {
        this(null, name, value, null);
    }

    /**
     * Constructor with the claim namespace, name and value
     *
     * @param namespace {@link String}
     * @param name  {@link String} the claim name
     * @param value {@link Object} the value of the claim
     */
    protected MdocClaim(String namespace, String name, Object value) {
        this(namespace, name, value, null);
    }

    /**
     * Constructor with the claim namespace, digestId, name and value
     *
     * @param namespace {@link String}
     * @param digestId integer identifier of the claim digest
     * @param name  {@link String} the claim name
     * @param value {@link Object} the value of the claim
     */
    protected MdocClaim(String namespace, int digestId, String name, Object value) {
        this(namespace, digestId, name, value, null);
    }

    /**
     * Constructor with the claim namespace, name, value and salt
     *
     * @param namespace {@link String}
     * @param name  {@link String} the claim name
     * @param value {@link Object} the value of the claim
     * @param salt byte array containing a salt with a high entropy used for a digest computation
     */
    protected MdocClaim(String namespace, String name, Object value, byte[] salt) {
        super(name, value);
        this.namespace = namespace;
        this.salt = salt;
    }

    /**
     * Constructor with the claim namespace, digestId, name, value and salt
     *
     * @param namespace {@link String}
     * @param digestId integer identifier of the claim digest
     * @param name  {@link String} the claim name
     * @param value {@link Object} the value of the claim
     * @param salt byte array containing a salt with a high entropy used for a digest computation
     */
    protected MdocClaim(String namespace, int digestId, String name, Object value, byte[] salt) {
        super(name, value);
        this.namespace = namespace;
        this.digestId = digestId;
        this.salt = salt;
    }

    /**
     * Gets the applicable namespace of the element claim
     *
     * @return {@link String}
     */
    public String getNamespace() {
        return namespace;
    }

    /**
     * Gets the digestId of the claim hash
     *
     * @return {@link Integer}
     */
    public Integer getDigestId() {
        return digestId;
    }

    /**
     * Sets a digest id
     *
     * @param digestId {@link Integer}
     */
    public void setDigestId(Integer digestId) {
        this.digestId = digestId;
    }

    /**
     * Gets the salt
     *
     * @return byte array
     */
    public byte[] getSalt() {
        return salt;
    }

    /**
     * Sets the salt
     *
     * @param salt byte array
     */
    public void setSalt(byte[] salt) {
        this.salt = salt;
    }

    /**
     * Gets whether the claim is void (no element identifier or namespace is included)
     *
     * @return whether the claim is void
     */
    public boolean isVoid() {
        return getNamespace() == null && getName() == null;
    }

    /**
     * Gets a CBOR representation of the claim value
     *
     * @return {@link CBORObject}
     */
    public CBORObject getValueAsCbor() {
        return CBORObjectFactory.toCBORObject(getValue());
    }

    /**
     * Creates a copy of the MdocClaim
     *
     * @return {@link MdocClaim} a copy
     */
    public MdocClaim copy() {
        MdocClaim copy = initCopy();
        if (getDigestId() != null) {
            copy.digestId = getDigestId();
        }
        if (getSalt() != null) {
            copy.salt = getSalt();
        }
        return copy;
    }

    /**
     * Instantiates a copy MdocClaim
     *
     * @return {@link MdocClaim}
     */
    protected MdocClaim initCopy() {
        return new MdocClaim(getNamespace(), getName(), getValue());
    }

    @Override
    public String toString() {
        return "MdocClaim [" +
                "name='" + getName() + '\'' +
                ", value=" + getValue() +
                ", namespace='" + namespace + '\'' +
                ", digestId=" + digestId +
                ", salt=" + Arrays.toString(salt) +
                "] " + super.toString();
    }

}
