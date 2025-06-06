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
package eu.europa.esig.dss.evidencerecord.xml.digest;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.evidencerecord.common.digest.AbstractDataObjectDigestBuilder;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.spi.DSSMessageDigestCalculator;
import eu.europa.esig.dss.xml.utils.DomUtils;
import eu.europa.esig.dss.xml.utils.XMLCanonicalizer;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * Generates digests for data objects to be protected by an IETF RFC 6283 XMLERS evidence-record
 *
 */
public class XMLEvidenceRecordDataObjectDigestBuilder extends AbstractDataObjectDigestBuilder {

    /** Canonicalization method to be used on processing of XML documents */
    private String canonicalizationMethod;

    /**
     * Constructor to create a builder for computing digest on the given binaries using a SHA-256 digest algorithm
     *
     * @param binaries byte array to compute hash on
     */
    public XMLEvidenceRecordDataObjectDigestBuilder(final byte[] binaries) {
        this(binaries, DigestAlgorithm.SHA256);
    }

    /**
     * Constructor to create a builder for computing digest on the given InputStream using a SHA-256 digest algorithm
     *
     * @param inputStream {@link InputStream} to compute hash on
     */
    public XMLEvidenceRecordDataObjectDigestBuilder(final InputStream inputStream) {
        this(inputStream, DigestAlgorithm.SHA256);
    }

    /**
     * Constructor to create a builder for computing digest on the given document using a SHA-256 digest algorithm
     *
     * @param document {@link DSSDocument} to compute hash on
     */
    public XMLEvidenceRecordDataObjectDigestBuilder(final DSSDocument document) {
        this(document, DigestAlgorithm.SHA256);
    }

    /**
     * Constructor to create a builder for computing digest on the given binaries using a provided digest algorithm
     *
     * @param binaries {@link DigestAlgorithm} to compute hash on
     * @param digestAlgorithm {@link DigestAlgorithm} to be used on hash computation
     */
    public XMLEvidenceRecordDataObjectDigestBuilder(final byte[] binaries, final DigestAlgorithm digestAlgorithm) {
        super(binaries, digestAlgorithm);
    }

    /**
     * Constructor to create a builder for computing digest on the given InputStream using a provided digest algorithm
     *
     * @param inputStream {@link InputStream} to compute hash on
     * @param digestAlgorithm {@link DigestAlgorithm} to be used on hash computation
     */
    public XMLEvidenceRecordDataObjectDigestBuilder(final InputStream inputStream, final DigestAlgorithm digestAlgorithm) {
        super(inputStream, digestAlgorithm);
    }

    /**
     * Constructor to create a builder for computing digest on the given document using a provided digest algorithm
     *
     * @param document {@link DSSDocument} to compute hash on
     * @param digestAlgorithm {@link DigestAlgorithm} to be used on hash computation
     */
    public XMLEvidenceRecordDataObjectDigestBuilder(final DSSDocument document, final DigestAlgorithm digestAlgorithm) {
        super(document, digestAlgorithm);
    }

    /**
     * Sets a canonicalization method to be used
     * Default: "http://www.w3.org/TR/2001/REC-xml-c14n-20010315" canonicalization algorithm
     *
     * @param canonicalizationMethod {@link String}
     * @return this {@link XMLEvidenceRecordDataObjectDigestBuilder}
     */
    public XMLEvidenceRecordDataObjectDigestBuilder setCanonicalizationMethod(String canonicalizationMethod) {
        this.canonicalizationMethod = canonicalizationMethod;
        return this;
    }

    @Override
    public Digest build() {
        DSSDocument providedDocument = document;
        if (inputStream != null) {
            providedDocument = new InMemoryDocument(inputStream);
        }
        if (providedDocument == null) {
            throw new IllegalStateException("DSSDocument or InputStream shall be defined!");
        }
        byte[] hashValue;
        if (DomUtils.isDOM(providedDocument)) {
            hashValue = getDigestValueOnCanonicalizedDocument(providedDocument);
        } else {
            hashValue = providedDocument.getDigestValue(digestAlgorithm);
        }
        return new Digest(digestAlgorithm, hashValue);
    }

    private byte[] getDigestValueOnCanonicalizedDocument(DSSDocument document) {
        final DSSMessageDigestCalculator messageDigestCalculator = new DSSMessageDigestCalculator(digestAlgorithm);
        try (InputStream is = document.openStream(); OutputStream os = messageDigestCalculator.getOutputStream()) {
            XMLCanonicalizer.createInstance(canonicalizationMethod).canonicalize(is, os);
            return messageDigestCalculator.getMessageDigest(digestAlgorithm).getValue();
        } catch (IOException e) {
            throw new DSSException(String.format("Unable to read document with name '%s'! Reason : %s", document.getName(), e.getMessage()), e);
        }
    }

}
