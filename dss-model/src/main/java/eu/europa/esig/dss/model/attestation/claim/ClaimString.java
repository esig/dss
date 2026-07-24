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
package eu.europa.esig.dss.model.attestation.claim;

import java.util.Objects;

/**
 * Represents a String encoded (selectively) disclosable claim
 *
 */
public class ClaimString extends AbstractClaim {

    private static final long serialVersionUID = -4405160230836421331L;

    /** String value of the claim */
    private final String value;

    /**
     * Default constructor
     *
     * @param value {@link String} value of the claim
     */
    public ClaimString(final String value) {
        this(null, value);
    }

    /**
     * Constructor with claim header name provided
     *
     * @param name {@link String} claim header name
     * @param value {@link String} value of the claim
     */
    public ClaimString(final String name, final String value) {
        this(name, value, false);
    }

    /**
     * Constructor with claim name and selectively disclosable revocation provided
     *
     * @param name {@link String} claim header name
     * @param value {@link String} value of the claim
     * @param selectivelyDisclosable whether the claim is selectively disclosable
     *                               (can be TRUE only when the value of claim is provided in a form of disclosure)
     */
    public ClaimString(final String name, final String value, final boolean selectivelyDisclosable) {
        this(name, value, selectivelyDisclosable, null);
    }

    /**
     * Constructor with claim name and selectively disclosable revocation and a parent claim provided
     *
     * @param name {@link String} claim header name
     * @param value {@link String} value of the claim
     * @param selectivelyDisclosable whether the claim is selectively disclosable
     *                               (can be TRUE only when the value of claim is provided in a form of disclosure)
     * @param parent {@link Claim} representing the parent claim, when applicable
     */
    public ClaimString(final String name, final String value, final boolean selectivelyDisclosable, final Claim parent) {
        this(name, null, value, selectivelyDisclosable, parent);
    }

    /**
     * Constructor with claim name, namespace and selectively disclosable revocation and a parent claim provided
     *
     * @param name {@link String} claim header name
     * @param namespace {@link String} representing the original namespace (NOTE: used in mdoc)
     * @param value {@link String} value of the claim
     * @param selectivelyDisclosable whether the claim is selectively disclosable
     *                               (can be TRUE only when the value of claim is provided in a form of disclosure)
     * @param parent {@link Claim} representing the parent claim, when applicable
     */
    public ClaimString(final String name, final String namespace, final String value,
                       final boolean selectivelyDisclosable, final Claim parent) {
        super(name, namespace, selectivelyDisclosable, parent);
        this.value = value;
    }


    @Override
    public String getStringValue() {
        return value;
    }

    @Override
    public boolean isStringValueType() {
        return true;
    }

    @Override
    public String getValueAsString() {
        return value;
    }

    @Override
    public boolean isNullOrEmpty() {
        return value == null;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        if (!super.equals(o)) return false;

        ClaimString that = (ClaimString) o;
        return Objects.equals(value, that.value);
    }

    @Override
    public int hashCode() {
        int result = super.hashCode();
        result = 31 * result + Objects.hashCode(value);
        return result;
    }

}
