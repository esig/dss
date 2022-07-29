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
package eu.europa.esig.dss.pdf;

import eu.europa.esig.dss.model.DSSDocument;

import java.io.Serializable;

/**
 * This class is used as a DTO containing cached data to be used to accelerate the signature creation process
 *
 */
public class PdfSignatureCache implements Serializable {

    private static final long serialVersionUID = 8200423861085879279L;

    /**
     * Cached digest value of the covered ByteRange
     */
    private byte[] digest;

    /**
     * Represents a pre-generated PDF document, used for digest computation,
     * preserving a /Contents space for CMS Signed Data inclusion
     */
    private DSSDocument toBeSignedDocument;

    /**
     * Default constructor instantiating object with null values
     */
    public PdfSignatureCache() {
    }

    /**
     * Gets digest of the ByteRange
     *
     * @return byte array representing digest value
     */
    public byte[] getDigest() {
        return digest;
    }

    /**
     * Sets digest of the ByteRange
     *
     * @param digest byte array
     */
    public void setDigest(byte[] digest) {
        this.digest = digest;
    }

    /**
     * Gets ToBeSigned document
     *
     * @return {@link DSSDocument}
     */
    public DSSDocument getToBeSignedDocument() {
        return toBeSignedDocument;
    }

    /**
     * Sets ToBeSigned document
     *
     * @param toBeSignedDocument {@link DSSDocument}
     */
    public void setToBeSignedDocument(DSSDocument toBeSignedDocument) {
        this.toBeSignedDocument = toBeSignedDocument;
    }

}
