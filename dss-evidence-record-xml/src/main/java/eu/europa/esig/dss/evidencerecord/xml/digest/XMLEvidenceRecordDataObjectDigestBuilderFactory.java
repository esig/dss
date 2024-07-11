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
package eu.europa.esig.dss.evidencerecord.xml.digest;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.spi.x509.evidencerecord.digest.DataObjectDigestBuilder;
import eu.europa.esig.dss.spi.x509.evidencerecord.digest.DataObjectDigestBuilderFactory;

/**
 * Creates a new instance of {@code eu.europa.esig.dss.evidencerecord.xml.digest.XMLEvidenceRecordDataObjectDigestBuilder}
 * to compute hashes for RFC 6283 XMLERS evidence records
 *
 */
public class XMLEvidenceRecordDataObjectDigestBuilderFactory implements DataObjectDigestBuilderFactory {

    /** Canonicalization method to be used on processing of XML documents */
    private String canonicalizationMethod;

    /**
     * Default constructor
     */
    public XMLEvidenceRecordDataObjectDigestBuilderFactory() {
        // empty
    }

    /**
     * Sets a canonicalization method to be used
     * Default: "http://www.w3.org/TR/2001/REC-xml-c14n-20010315" canonicalization algorithm
     *
     * @param canonicalizationMethod {@link String}
     * @return this {@link XMLEvidenceRecordDataObjectDigestBuilderFactory}
     */
    public XMLEvidenceRecordDataObjectDigestBuilderFactory setCanonicalizationMethod(String canonicalizationMethod) {
        this.canonicalizationMethod = canonicalizationMethod;
        return this;
    }

    @Override
    public DataObjectDigestBuilder create(DSSDocument document) {
        final XMLEvidenceRecordDataObjectDigestBuilder dataObjectDigestBuilder =
                new XMLEvidenceRecordDataObjectDigestBuilder(document);
        dataObjectDigestBuilder.setCanonicalizationMethod(canonicalizationMethod);
        return dataObjectDigestBuilder;
    }

    @Override
    public DataObjectDigestBuilder create(DSSDocument document, DigestAlgorithm digestAlgorithm) {
        final XMLEvidenceRecordDataObjectDigestBuilder dataObjectDigestBuilder =
                new XMLEvidenceRecordDataObjectDigestBuilder(document, digestAlgorithm);
        dataObjectDigestBuilder.setCanonicalizationMethod(canonicalizationMethod);
        return dataObjectDigestBuilder;
    }

}
