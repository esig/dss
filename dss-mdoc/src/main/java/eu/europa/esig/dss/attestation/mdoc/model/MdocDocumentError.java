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
package eu.europa.esig.dss.attestation.mdoc.model;

/**
 * Contains error cde for not returned document within an mdoc structure
 *
 */
public class MdocDocumentError {

    /** DocType of the corresponding document */
    private String docType;

    /** Error code for the concerned document */
    private Long errorCode;

    /**
     * Default constructor
     */
    public MdocDocumentError() {
        // empty
    }

    /**
     * Gets the docType of the related document
     *
     * @return {@link String}
     */
    public String getDocType() {
        return docType;
    }

    /**
     * Sets the docType of the related document
     *
     * @param docType {@link String}
     */
    public void setDocType(String docType) {
        this.docType = docType;
    }

    /**
     * Gets an error code for the concerned document
     *
     * @return {@link Long}
     */
    public Long getErrorCode() {
        return errorCode;
    }

    /**
     * Sets an error code for the concerned document
     *
     * @param errorCode {@link Long}
     */
    public void setErrorCode(Long errorCode) {
        this.errorCode = errorCode;
    }

}
