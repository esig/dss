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
package eu.europa.esig.dss.model.attestation;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.attestation.claim.VerifiedClaim;

import java.io.Serializable;
import java.util.Arrays;
import java.util.EnumMap;
import java.util.Objects;

/**
 * Generic implementation of a selective disclosure on validation
 *
 */
public abstract class SelectivelyDisclosableClaim implements Serializable {

    private static final long serialVersionUID = -6025755119813037143L;

    /** Salt value */
    protected byte[] salt;

    /** Value of the disclosure claim */
    protected VerifiedClaim claim;

    /** Cached map containing computed digest values */
    private final EnumMap<DigestAlgorithm, Digest> digestMap = new EnumMap<>(DigestAlgorithm.class);

    /**
     * Default constructor
     */
    protected SelectivelyDisclosableClaim() {
        // empty
    }

    /**
     * Gets salt of the disclosure
     *
     * @return byte array representing disclosure's salt
     */
    public byte[] getSalt() {
        return salt;
    }

    /**
     * Gets the name of the disclosure claim
     *
     * @return {@link String}
     */
    public String getName() {
        return claim != null ? claim.getName() : null;
    }

    /**
     * Gets the value of the disclosure claim value
     *
     * @return {@link VerifiedClaim}
     */
    public VerifiedClaim getClaimValue() {
        return claim;
    }

    /**
     * Gets the applicable namespace (mdoc only)
     *
     * @return {@link String}
     */
    public String getNamespace() {
        return null;
    }

    /**
     * Gets the digest ID for the issuer data authentication (mdoc only)
     *
     * @return {@link Long}
     */
    public Long getDigestId() {
        return null;
    }

    /**
     * Gets digest value of the for the {@code DigestAlgorithm}
     *
     * @param digestAlgorithm {@link DigestAlgorithm} to be used to compute digest with
     * @return {@link Digest}
     */
    public Digest getDigest(DigestAlgorithm digestAlgorithm) {
        if (digestAlgorithm == null) {
            return new Digest(); // empty digest
        }
        return digestMap.computeIfAbsent(digestAlgorithm, d -> computeDigest(digestAlgorithm));
    }

    /**
     * Computes digest according to the rules for the given attestation presentation type
     *
     * @param digestAlgorithm {@link DigestAlgorithm} to be used on the hash computation
     * @return {@link Digest}
     */
    protected abstract Digest computeDigest(DigestAlgorithm digestAlgorithm);

    @Override
    public boolean equals(Object object) {
        if (this == object) return true;
        if (object == null || getClass() != object.getClass()) return false;

        SelectivelyDisclosableClaim that = (SelectivelyDisclosableClaim) object;
        return Arrays.equals(salt, that.salt)
                && Objects.equals(claim, that.claim);
    }

    @Override
    public int hashCode() {
        int result = Arrays.hashCode(salt);
        result = 31 * result + Objects.hashCode(claim);
        return result;
    }

}
