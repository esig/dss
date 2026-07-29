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
import java.util.Objects;

/**
 * DTO representing a selective disclosure
 *
 */
public class DisclosureDTO implements Serializable {

    private static final long serialVersionUID = -4519653477231360037L;

    /** (Mdoc) namespace of the disclosure */
    private String namespace;

    /** (Mdoc) digestId within the namespace of the disclosure */
    private Integer digestId;

    /** Value of the disclosure */
    private String value;

    /**
     * Empty constructor
     */
    public DisclosureDTO() {
        super();
    }

    /**
     * Constructor with a value (SD-JWT)
     *
     * @param value {@link String}
     */
    public DisclosureDTO(String value) {
        this.value = value;
    }

    /**
     * Constructor with a value, namespace and digestId (mdoc)
     *
     * @param namespace {@link String}
     * @param digestId {@link Integer}
     * @param value {@link String}
     */
    public DisclosureDTO(String namespace, Integer digestId, String value) {
        this.namespace = namespace;
        this.digestId = digestId;
        this.value = value;
    }

    /**
     * Gets the namespace of the selectively disclosable data item (mdoc)
     *
     * @return {@link String}
     */
    public String getNamespace() {
        return namespace;
    }

    /**
     * Sets the namespace of the selectively disclosable data item (mdoc)
     *
     * @param namespace {@link String}
     */
    public void setNamespace(String namespace) {
        this.namespace = namespace;
    }

    /**
     * Gets the digestId of the selectively disclosable data item (mdoc)
     *
     * @return {@link Integer}
     */
    public Integer getDigestId() {
        return digestId;
    }

    /**
     * Sets the digestId of the selectively disclosable data item (mdoc)
     *
     * @param digestId {@link Integer}
     */
    public void setDigestId(Integer digestId) {
        this.digestId = digestId;
    }

    /**
     * Gets the value of the selective disclosure
     *
     * @return {@link String}
     */
    public String getValue() {
        return value;
    }

    /**
     * Sets the value of the selective disclosure
     *
     * @param value {@link String}
     */
    public void setValue(String value) {
        this.value = value;
    }

    @Override
    public String toString() {
        return "DisclosureDTO [" +
                "namespace='" + namespace + '\'' +
                ", digestId=" + digestId +
                ", value='" + value + '\'' +
                ']';
    }

    @Override
    public boolean equals(Object object) {
        if (this == object) return true;
        if (object == null || getClass() != object.getClass()) return false;

        DisclosureDTO that = (DisclosureDTO) object;
        return Objects.equals(namespace, that.namespace)
                && Objects.equals(digestId, that.digestId)
                && Objects.equals(value, that.value);
    }

    @Override
    public int hashCode() {
        int result = Objects.hashCode(namespace);
        result = 31 * result + Objects.hashCode(digestId);
        result = 31 * result + Objects.hashCode(value);
        return result;
    }

}
