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
package eu.europa.esig.dss.xades.validation;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.utils.Utils;
import org.apache.xml.security.signature.XMLSignatureInput;

import java.io.InputStream;

/**
 * This class represents an implementation of an {@code XMLSignatureInput} created on a base of {@code DSSDocument}
 *
 */
public class DSSDocumentXMLSignatureInput extends XMLSignatureInput {

    /** The detached document to be provided */
    private final DSSDocument document;

    /** Pre-calculated digest value of the object in base64. */
    private String preCalculatedDigest;

    /**
     * Default constructor for an {@code XMLSignatureInput} from a detached document
     *
     * @param document {@link DSSDocument}
     */
    public DSSDocumentXMLSignatureInput(final DSSDocument document) {
        super(toInputStream(document));
        this.document = document;
    }

    private static InputStream toInputStream(DSSDocument document) {
        return document.openStream();
    }

    /**
     * Constructor for an {@code XMLSignatureInput} from a base64-encoded document digest
     *
     * @param document {@link DSSDocument}
     * @param digestAlgorithm {@link DigestAlgorithm} to be used for a digest computation
     */
    protected DSSDocumentXMLSignatureInput(final DSSDocument document, final DigestAlgorithm digestAlgorithm) {
        super(getBase64Digest(document, digestAlgorithm));
        this.document = document;
        this.preCalculatedDigest = super.getPreCalculatedDigest(); // get digest provided in constructor
    }

    private static String getBase64Digest(DSSDocument document, DigestAlgorithm digestAlgorithm) {
        byte[] digestValue = document.getDigestValue(digestAlgorithm);
        return Utils.toBase64(digestValue);
    }

    @Override
    public String getMIMEType() {
        if (document.getMimeType() != null) {
            return document.getMimeType().getMimeTypeString();
        }
        return null;
    }

    /**
     * Returns a document name
     *
     * @return {@link String}
     */
    public String getDocumentName() {
        return document.getName();
    }

    @Override
    public boolean isPreCalculatedDigest() {
        return preCalculatedDigest != null;
    }

    @Override
    public String getPreCalculatedDigest() {
        Utils.closeQuietly(getOctetStreamReal()); // close original InputStream
        return preCalculatedDigest;
    }

    /**
     * Sets the pre-calculated digest to avoid document streaming
     *
     * @param preCalculatedDigest {@link String} base64-encoded value
     */
    public void setPreCalculatedDigest(String preCalculatedDigest) {
        this.preCalculatedDigest = preCalculatedDigest;
    }

}
