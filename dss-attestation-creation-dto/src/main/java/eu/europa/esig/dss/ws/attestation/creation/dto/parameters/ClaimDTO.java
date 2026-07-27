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
package eu.europa.esig.dss.ws.attestation.creation.dto.parameters;

import java.io.Serializable;
import java.util.Arrays;
import java.util.Objects;

/**
 * DTO representing a custom claim
 *
 */
public class ClaimDTO implements Serializable {

    private static final long serialVersionUID = -8447619549334915406L;

    /** Namespace of the element claim (mdoc only) */
    private String namespace;

    /** Integer identifier of the claim digest (mdoc only) */
    private Integer digestId;

    /** The name of the attestation claim */
    private String name;

    /** The value of the attestation claim */
    private ClaimValueDTO value;

    /** Identifies whether the claim is selectively disclosable */
    private Boolean selectivelyDisclosable;

    /** Salt of the selectively disclosable claim, when applicable */
    private byte[] salt;

    /**
     * Default constructor
     */
    public ClaimDTO() {
        //empty
    }

    /**
     * Constructor with a value
     *
     * @param value {@link ClaimValueDTO}
     */
    public ClaimDTO(ClaimValueDTO value) {
        this(null, value);
    }

    /**
     * Constructor with a value and whether it is selectively disclosable
     *
     * @param value {@link ClaimValueDTO}
     * @param selectivelyDisclosable {@link Boolean}
     */
    public ClaimDTO(ClaimValueDTO value, Boolean selectivelyDisclosable) {
        this(null, value, selectivelyDisclosable);
    }

    /**
     * Constructor with a name and value
     *
     * @param name {@link String}
     * @param value {@link ClaimValueDTO}
     */
    public ClaimDTO(String name, ClaimValueDTO value) {
        this(null, name, value);
    }

    /**
     * Constructor with a name and value and whether it is selectively disclosable
     *
     * @param name {@link String}
     * @param value {@link ClaimValueDTO}
     * @param selectivelyDisclosable {@link Boolean}
     */
    public ClaimDTO(String name, ClaimValueDTO value, Boolean selectivelyDisclosable) {
        this.name = name;
        this.value = value;
        this.selectivelyDisclosable = selectivelyDisclosable;
    }

    /**
     * Constructor with a namespace, name and value
     *
     * @param namespace {@link String}
     * @param name {@link String}
     * @param value {@link ClaimValueDTO}
     */
    public ClaimDTO(String namespace, String name, ClaimValueDTO value) {
        this.namespace = namespace;
        this.name = name;
        this.value = value;
    }

    /**
     * Gets the namespace (mdoc only)
     *
     * @return {@link String}
     */
    public String getNamespace() {
        return namespace;
    }

    /**
     * Sets the namespace (mdoc only)
     *
     * @param namespace {@link String}
     */
    public void setNamespace(String namespace) {
        this.namespace = namespace;
    }

    /**
     * Gets the digest identifier (mdoc only)
     *
     * @return {@link Integer}
     */
    public Integer getDigestId() {
        return digestId;
    }

    /**
     * Sets the digest identifier (mdoc only)
     *
     * @param digestId {@link Integer}
     */
    public void setDigestId(Integer digestId) {
        this.digestId = digestId;
    }

    /**
     * Gets the claim name
     *
     * @return {@link String}
     */
    public String getName() {
        return name;
    }

    /**
     * Sets the claim name
     *
     * @param name {@link String}
     */
    public void setName(String name) {
        this.name = name;
    }

    /**
     * Gets the claim value
     *
     * @return {@link ClaimValueDTO}
     */
    public ClaimValueDTO getValue() {
        return value;
    }

    /**
     * Sets the claim value
     *
     * @param value {@link ClaimValueDTO}
     */
    public void setValue(ClaimValueDTO value) {
        this.value = value;
    }

    /**
     * Gets whether the claim is selectively disclosable
     *
     * @return {@link Boolean}
     */
    public Boolean getSelectivelyDisclosable() {
        return selectivelyDisclosable;
    }

    /**
     * Sets whether the claim is selectively disclosable
     *
     * @param selectivelyDisclosable {@link Boolean}
     */
    public void setSelectivelyDisclosable(Boolean selectivelyDisclosable) {
        this.selectivelyDisclosable = selectivelyDisclosable;
    }

    /**
     * Gets the salt of the selectively disclosable claim
     *
     * @return byte[]
     */
    public byte[] getSalt() {
        return salt;
    }

    /**
     * Sets the salt of the selectively disclosable claim.
     * (Optional). Generated automatically if not provided.
     *
     * @param salt byte[]
     */
    public void setSalt(byte[] salt) {
        this.salt = salt;
    }

    @Override
    public String toString() {
        return "ClaimDTO [" +
                "namespace='" + namespace + '\'' +
                ", digestId=" + digestId +
                ", name='" + name + '\'' +
                ", value=" + value +
                ", selectivelyDisclosable=" + selectivelyDisclosable +
                ", salt=" + Arrays.toString(salt) +
                ']';
    }

    @Override
    public boolean equals(Object object) {
        if (this == object) return true;
        if (object == null || getClass() != object.getClass()) return false;

        ClaimDTO claimDTO = (ClaimDTO) object;
        return Objects.equals(namespace, claimDTO.namespace)
                && Objects.equals(digestId, claimDTO.digestId)
                && Objects.equals(name, claimDTO.name)
                && Objects.equals(value, claimDTO.value)
                && Objects.equals(selectivelyDisclosable, claimDTO.selectivelyDisclosable)
                && Arrays.equals(salt, claimDTO.salt);
    }

    @Override
    public int hashCode() {
        int result = Objects.hashCode(namespace);
        result = 31 * result + Objects.hashCode(digestId);
        result = 31 * result + Objects.hashCode(name);
        result = 31 * result + Objects.hashCode(value);
        result = 31 * result + Objects.hashCode(selectivelyDisclosable);
        result = 31 * result + Arrays.hashCode(salt);
        return result;
    }

}
