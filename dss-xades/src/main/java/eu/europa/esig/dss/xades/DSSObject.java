/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * 
 * This file is part of the "DSS - Digital Signature Services" project.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.xades;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.MimeType;

import java.io.Serializable;

/**
 * Allows creation of custom ds:Object element
 */
public class DSSObject implements Serializable {

    private static final long serialVersionUID = -4680201985310575707L;

    /**
     * Represents a content of the ds:Object element
     * Can be XML or any other format (e.g. base64 encoded)
     */
    private DSSDocument content;

    /**
     * Represents a value for the "Id" attribute
     */
    private String id;

    /**
     * Represents a value for the "MimeType" attribute
     */
    private MimeType mimeType;

    /**
     * Represents a value for the "Encoding" attribute
     */
    private String encodingAlgorithm;

    /**
     * Default constructor
     */
    public DSSObject() {
    }

    /**
     * Gets the content of the ds:Object element to be created
     *
     * @return {@link DSSDocument}
     */
    public DSSDocument getContent() {
        return content;
    }

    /**
     * Sets the content of ds:Object element to be created
     * Can be XML or any other format (e.g. base64 encoded)
     *
     * @param content {@link DSSDocument}
     */
    public void setContent(DSSDocument content) {
        this.content = content;
    }

    /**
     * Gets the Id
     *
     * @return {@link String}
     */
    public String getId() {
        return id;
    }

    /**
     * Sets the value for the "Id" attribute
     *
     * @param id {@link String}
     */
    public void setId(String id) {
        this.id = id;
    }

    /**
     * Gets the MimeType
     *
     * @return {@link MimeType}
     */
    public MimeType getMimeType() {
        return mimeType;
    }

    /**
     * Sets the value for the "MimeType" attribute
     *
     * @param mimeType {@link MimeType}
     */
    public void setMimeType(MimeType mimeType) {
        this.mimeType = mimeType;
    }

    /**
     * Gets the encoding algorithm
     *
     * @return {@link String}
     */
    public String getEncodingAlgorithm() {
        return encodingAlgorithm;
    }

    /**
     * Sets the value for the "encoding" attribute
     *
     * @param encodingAlgorithm {@link String}
     */
    public void setEncodingAlgorithm(String encodingAlgorithm) {
        this.encodingAlgorithm = encodingAlgorithm;
    }

}
