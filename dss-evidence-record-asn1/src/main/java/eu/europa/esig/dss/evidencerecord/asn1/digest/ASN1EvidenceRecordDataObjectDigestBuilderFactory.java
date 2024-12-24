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
package eu.europa.esig.dss.evidencerecord.asn1.digest;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.spi.x509.evidencerecord.digest.DataObjectDigestBuilder;
import eu.europa.esig.dss.spi.x509.evidencerecord.digest.DataObjectDigestBuilderFactory;

/**
 * Creates a new instance of {@code eu.europa.esig.dss.evidencerecord.asn1.digest.ASN1EvidenceRecordDataObjectDigestBuilder}
 * to compute hashes for RFC 4998 ASN.1  Evidence Record Syntax (ERS) evidence records
 */
public class ASN1EvidenceRecordDataObjectDigestBuilderFactory implements DataObjectDigestBuilderFactory {

    /**
     * Default constructor
     */
    public ASN1EvidenceRecordDataObjectDigestBuilderFactory() {
        // empty
    }

    @Override
    public DataObjectDigestBuilder create(DSSDocument document) {
        return new ASN1EvidenceRecordDataObjectDigestBuilder(document);
    }

    @Override
    public DataObjectDigestBuilder create(DSSDocument document, DigestAlgorithm digestAlgorithm) {
        return new ASN1EvidenceRecordDataObjectDigestBuilder(document, digestAlgorithm);
    }

}
