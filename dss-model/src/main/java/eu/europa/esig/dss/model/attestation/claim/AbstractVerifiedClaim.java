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

import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Abstract implementation of a disclosable claim, contains common information for the (selectively) disclosable claims
 *
 */
public abstract class AbstractVerifiedClaim implements VerifiedClaim {

    private static final long serialVersionUID = -6060146078508116153L;

    /** Name of the claim */
    private String name;

    /** Whether the claim is selectively disclosable */
    private boolean selectivelyDisclosable;

    /** Namespace of the claim's origin (used in mdoc) */
    private String namespace;

    /** Parent claim, containing the current claim in its body */
    private VerifiedClaim parent;

    /**
     * Default constructor
     */
    protected AbstractVerifiedClaim() {
        // empty
    }

    /**
     * Constructor with claim name provided
     *
     * @param name {@link String}
     */
    protected AbstractVerifiedClaim(String name) {
        this.name = name;
    }

    /**
     * Constructor with claim name and selectively disclosable revocation provided
     *
     * @param name {@link String}
     * @param selectivelyDisclosable whether the claim is selectively disclosable
     *                               (can be TRUE only when the value of claim is provided in a form of disclosure)
     */
    protected AbstractVerifiedClaim(String name, boolean selectivelyDisclosable) {
        this(name, selectivelyDisclosable, null);
    }

    /**
     * Constructor with claim name and selectively disclosable revocation and parent claim provided
     *
     * @param name {@link String}
     * @param selectivelyDisclosable whether the claim is selectively disclosable
     *                               (can be TRUE only when the value of claim is provided in a form of disclosure)
     * @param parent {@link VerifiedClaim} representing the parent claim, when applicable
     */
    protected AbstractVerifiedClaim(String name, boolean selectivelyDisclosable, VerifiedClaim parent) {
        this(name, null, selectivelyDisclosable, parent);
    }

    /**
     * Constructor with claim name, namespace and selectively disclosable revocation and parent claim provided
     *
     * @param name {@link String}
     * @param namespace {@link String}
     * @param selectivelyDisclosable whether the claim is selectively disclosable
     *                               (can be TRUE only when the value of claim is provided in a form of disclosure)
     * @param parent {@link VerifiedClaim} representing the parent claim, when applicable
     */
    protected AbstractVerifiedClaim(String name, String namespace, boolean selectivelyDisclosable, VerifiedClaim parent) {
        this.name = name;
        this.namespace = namespace;
        this.selectivelyDisclosable = selectivelyDisclosable;
        this.parent = parent;
    }

    @Override
    public String getName() {
        return name;
    }

    @Override
    public boolean isSelectivelyDisclosable() {
        return selectivelyDisclosable;
    }

    @Override
    public String getNamespace() {
        return namespace;
    }

    @Override
    public VerifiedClaim getParent() {
        return parent;
    }

    @Override
    public String getStringValue() {
        return null;
    }

    @Override
    public Number getNumberValue() {
        return null;
    }

    @Override
    public Map<String, VerifiedClaim> getMapValue() {
        return null;
    }

    @Override
    public Date getDateValue() {
        return null;
    }

    @Override
    public Boolean getBooleanValue() {
        return null;
    }

    @Override
    public byte[] getBinaryValue() {
        return null;
    }

    @Override
    public List<VerifiedClaim> getListValue() {
        return null;
    }

    @Override
    public boolean isStringValueType() {
        return false;
    }

    @Override
    public boolean isBinaryValueType() {
        return false;
    }

    @Override
    public boolean isBooleanValueType() {
        return false;
    }

    @Override
    public boolean isNumberValueType() {
        return false;
    }

    @Override
    public boolean isDateValueType() {
        return false;
    }

    @Override
    public boolean isArrayValueType() {
        return false;
    }

    @Override
    public boolean isMapValueType() {
        return false;
    }

    @Override
    public boolean isSubresourceIntegrityType() {
        return false;
    }

    @Override
    public boolean isNullValueType() {
        return false;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        AbstractVerifiedClaim that = (AbstractVerifiedClaim) o;
        return selectivelyDisclosable == that.selectivelyDisclosable
                && Objects.equals(name, that.name)
                && Objects.equals(parent, that.parent);
    }

    @Override
    public int hashCode() {
        int result = Objects.hashCode(name);
        result = 31 * result + Boolean.hashCode(selectivelyDisclosable);
        result = 31 * result + Objects.hashCode(parent);
        return result;
    }

    @Override
    public String toString() {
        return getClass().getSimpleName() + " {" +
                "'" + name + "'" + (selectivelyDisclosable ? " (disclosure)" : "") + ": " + getValueAsString() +
                '}';
    }

}
