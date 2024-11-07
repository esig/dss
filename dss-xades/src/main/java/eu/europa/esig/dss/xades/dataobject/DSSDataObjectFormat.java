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
package eu.europa.esig.dss.xades.dataobject;

import eu.europa.esig.dss.enumerations.ObjectIdentifier;

import java.io.Serializable;
import java.util.Objects;

/**
 * This class represents a {@code <xades:DataObjectFormat>} element as part of {@code <xades:SignedDataObjectProperties>}
 *
 */
public class DSSDataObjectFormat implements Serializable {

    private static final long serialVersionUID = -28123121170037681L;

    /**
     * Describes the data object
     */
    private String description;

    /**
     * Provides an identifier to the data object
     */
    private ObjectIdentifier objectIdentifier;

    /**
     * Defined the MimeType of the data object
     */
    private String mimeType;

    /**
     * Defines the encoding of the data object
     */
    private String encoding;

    /**
     * Provides a reference to the data object
     */
    private String objectReference;

    /**
     * Empty constructor
     */
    public DSSDataObjectFormat() {
        // empty
    }

    /**
     * Gets description of the data object
     *
     * @return {@link String}
     */
    public String getDescription() {
        return description;
    }

    /**
     * Sets description of the data object
     *
     * @param description {@link String}
     */
    public void setDescription(String description) {
        this.description = description;
    }

    /**
     * Gets object identifier (reference) of the data object
     *
     * @return {@link ObjectIdentifier}
     */
    public ObjectIdentifier getObjectIdentifier() {
        return objectIdentifier;
    }

    /**
     * Sets object identifier (reference) of the data object
     *
     * @param objectIdentifier {@link ObjectIdentifier}
     */
    public void setObjectIdentifier(ObjectIdentifier objectIdentifier) {
        this.objectIdentifier = objectIdentifier;
    }

    /**
     * Gets MimeType of the data object
     *
     * @return {@link String}
     */
    public String getMimeType() {
        return mimeType;
    }

    /**
     * Sets MimeType of the data object
     *
     * @param mimeType {@link String}
     */
    public void setMimeType(String mimeType) {
        this.mimeType = mimeType;
    }

    /**
     * Gets encoding of the data object
     *
     * @return {@link String}
     */
    public String getEncoding() {
        return encoding;
    }

    /**
     * Sets encoding of the data object
     *
     * @param encoding {@link String}
     */
    public void setEncoding(String encoding) {
        this.encoding = encoding;
    }

    /**
     * Gets reference to the data object
     *
     * @return {@link String}
     */
    public String getObjectReference() {
        return objectReference;
    }

    /**
     * Sets reference to the data object
     *
     * @param objectReference {@link String}
     */
    public void setObjectReference(String objectReference) {
        this.objectReference = objectReference;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof DSSDataObjectFormat)) return false;

        DSSDataObjectFormat that = (DSSDataObjectFormat) o;

        if (!Objects.equals(description, that.description)) return false;
        if (!Objects.equals(objectIdentifier, that.objectIdentifier))
            return false;
        if (!Objects.equals(mimeType, that.mimeType)) return false;
        if (!Objects.equals(encoding, that.encoding)) return false;
        return Objects.equals(objectReference, that.objectReference);
    }

    @Override
    public int hashCode() {
        int result = description != null ? description.hashCode() : 0;
        result = 31 * result + (objectIdentifier != null ? objectIdentifier.hashCode() : 0);
        result = 31 * result + (mimeType != null ? mimeType.hashCode() : 0);
        result = 31 * result + (encoding != null ? encoding.hashCode() : 0);
        result = 31 * result + (objectReference != null ? objectReference.hashCode() : 0);
        return result;
    }

    @Override
    public String toString() {
        return "DSSDataObjectFormat{" +
                "description='" + description + '\'' +
                ", objectIdentifier=" + objectIdentifier +
                ", mimeType='" + mimeType + '\'' +
                ", encoding='" + encoding + '\'' +
                ", objectReference='" + objectReference + '\'' +
                '}';
    }

}
