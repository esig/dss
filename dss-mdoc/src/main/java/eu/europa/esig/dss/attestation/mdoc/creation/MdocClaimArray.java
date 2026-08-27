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

import eu.europa.esig.dss.cbades.cbor.CBORArray;
import eu.europa.esig.dss.cbades.cbor.CBORObject;
import eu.europa.esig.dss.attestation.common.creation.claim.AttestationClaimArray;

import java.util.ArrayList;
import java.util.List;

/**
 * Represents a CBOR array to be incorporated as an ISO/IEC mdoc claim
 *
 */
public class MdocClaimArray extends MdocClaim implements AttestationClaimArray<MdocClaim> {

    private static final long serialVersionUID = -8747676551662684772L;

    /**
     * Create a {@link MdocClaimArray}. The name of the claim will be null.
     *
     * @return the created {@link MdocClaimArray}
     */
    public static MdocClaimArray create() {
        return new MdocClaimArray(new ArrayList<>());
    }

    /**
     * Create a {@link MdocClaimArray} with the provided name
     *
     * @param name {@link String} the name of the claim
     * @return the created {@link MdocClaimArray}
     */
    public static MdocClaimArray create(final String name) {
        return new MdocClaimArray(name, new ArrayList<>());
    }

    /**
     * Create a {@link MdocClaimArray}.
     * DigestId and salt will be computed during the payload generation process.
     *
     * @param namespace {@link String} the claim namespace
     * @param name {@link String} the claim name
     * @return the created {@link MdocClaim}
     */
    public static MdocClaimArray create(final String namespace, final String name) {
        return new MdocClaimArray(namespace, name, new ArrayList<>());
    }

    /**
     * Create a {@link MdocClaimArray} with the provided digestId.
     * Salt will be computed during the payload generation process.
     *
     * @param namespace {@link String} the claim namespace
     * @param digestId integer identifier of the claim digest
     * @param name {@link String} the claim name
     * @return the created {@link MdocClaim}
     */
    public static MdocClaimArray create(final String namespace, final int digestId, final String name) {
        return new MdocClaimArray(namespace, digestId, name, new ArrayList<>());
    }

    /**
     * Create a {@link MdocClaimArray} with the provided salt.
     * DigestId will be computed during the payload generation process.
     *
     * @param namespace {@link String} the claim namespace
     * @param name {@link String} the claim name
     * @param salt byte array containing a salt with a high entropy used for a digest computation
     * @return the created {@link MdocClaim}
     */
    public static MdocClaimArray create(final String namespace, final String name, final byte[] salt) {
        return new MdocClaimArray(namespace, name, new ArrayList<>(), salt);
    }

    /**
     * Create a {@link MdocClaimArray} with the provided digestId and salt.
     *
     * @param namespace {@link String} the claim namespace
     * @param digestId integer identifier of the claim digest
     * @param name {@link String} the claim name
     * @param salt byte array containing a salt with a high entropy used for a digest computation
     * @return the created {@link MdocClaim}
     */
    public static MdocClaimArray create(final String namespace, final int digestId, final String name, final byte[] salt) {
        return new MdocClaimArray(namespace, digestId, name, new ArrayList<>(), salt);
    }

    /**
     * Constructor with the claim value
     *
     * @param value {@link List} value
     */
    protected MdocClaimArray(List<?> value) {
        super(null, value);
    }

    /**
     * Constructor with the claim name and value
     *
     * @param name  {@link String} the claim name
     * @param value {@link List} value
     */
    protected MdocClaimArray(String name, List<?> value) {
        super(null, name, value);
    }

    /**
     * Constructor with the claim namespace, name and value
     *
     * @param namespace {@link String}
     * @param name  {@link String} the claim name
     * @param value {@link List} value
     */
    protected MdocClaimArray(String namespace, String name, List<?> value) {
        super(namespace, name, value);
    }

    /**
     * Constructor with the claim namespace, digestId, name and value
     *
     * @param namespace {@link String}
     * @param digestId integer identifier of the claim digest
     * @param name  {@link String} the claim name
     * @param value {@link List} value
     */
    protected MdocClaimArray(String namespace, int digestId, String name, List<?> value) {
        super(namespace, digestId, name, value);
    }

    /**
     * Constructor with the claim namespace, name, value and salt
     *
     * @param namespace {@link String}
     * @param name  {@link String} the claim name
     * @param value {@link List} value
     * @param salt byte array containing a salt with a high entropy used for a digest computation
     */
    protected MdocClaimArray(String namespace, String name, List<?> value, byte[] salt) {
        super(namespace, name, value, salt);
    }

    /**
     * Constructor with the claim namespace, digestId, name, value and salt
     *
     * @param namespace {@link String}
     * @param digestId integer identifier of the claim digest
     * @param name  {@link String} the claim name
     * @param value {@link List} value
     * @param salt byte array containing a salt with a high entropy used for a digest computation
     */
    protected MdocClaimArray(String namespace, int digestId, String name, List<?> value, byte[] salt) {
        super(namespace, digestId, name, value, salt);
    }

    @Override
    public void addElement(final MdocClaim element) {
        getElements().add(element);
    }

    @Override
    @SuppressWarnings("unchecked")
    public List<MdocClaim> getElements() {
        return (List<MdocClaim>) getValue();
    }

    @Override
    public CBORObject getValueAsCbor() {
        final CBORArray cborArray = new CBORArray();
        for (MdocClaim element : getElements()) {
            cborArray.add(element.getValueAsCbor());
        }
        return cborArray;
    }

    @Override
    protected MdocClaim initCopy() {
        return new MdocClaimArray(getNamespace(), getName(), getElements());
    }

}
