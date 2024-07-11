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
package eu.europa.esig.dss.evidencerecord.asn1.validation;

import eu.europa.esig.dss.diagnostic.CertificateRefWrapper;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.EvidenceRecordWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.CertificateRefOrigin;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DigestDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.utils.Utils;

import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class Asn1EvidenceRecordSimpleGroupValidationTest extends AbstractAsn1EvidenceRecordTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
    	return new FileDocument("src/test/resources/evidencerecord.ers");
    }

    @Override
    protected List<DSSDocument> getDetachedContents() {
        return Arrays.asList(
                new DigestDocument(DigestAlgorithm.SHA256, "EPRF0uQcTYjnF+PyR1a52z9fXpKZEAUx3d+jQAFfPos=", "1"),
                new DigestDocument(DigestAlgorithm.SHA256, "Oida+g+rN0DmsVgqZOgAex7lYghgYcgQth4CXl5idH0=", "2"),
                new DigestDocument(DigestAlgorithm.SHA256, "ZAiUg2B6CyVNPSiMgeaR4utRLwD3PPvMMBwXt0r3L7E=", "3"),
                new DigestDocument(DigestAlgorithm.SHA256, "go+iO1ByVKxsnCPfTfTkZ9WYK45d52Dc7mrV1lUl6Ho=", "4"),
                new DigestDocument(DigestAlgorithm.SHA256, "kG60U/JtBW9QHmxPX2+FH+I3q6FvtwS0G0kE1j6BT4Q=", "5"),
                new DigestDocument(DigestAlgorithm.SHA256, "zFMwgPw86LH0Py/DPEAqMA3uqMgatCJe0UwKJxifjD8=", "6")
        );
    }

    @Override
    protected void checkEvidenceRecords(DiagnosticData diagnosticData) {
        super.checkEvidenceRecords(diagnosticData);

        EvidenceRecordWrapper evidenceRecord = diagnosticData.getEvidenceRecords().get(0);

        int foundDataObjectCounter = 0;
        int orphanDataObjectsCounter = 0;
        for (XmlDigestMatcher digestMatcher : evidenceRecord.getDigestMatchers()) {
            if (DigestMatcherType.EVIDENCE_RECORD_ARCHIVE_OBJECT == digestMatcher.getType()) {
                ++foundDataObjectCounter;
            } else if (DigestMatcherType.EVIDENCE_RECORD_ORPHAN_REFERENCE == digestMatcher.getType()) {
                ++orphanDataObjectsCounter;
            }
        }
        assertEquals(6, foundDataObjectCounter);
        assertEquals(0, orphanDataObjectsCounter);
    }

    protected void checkTimestamp(DiagnosticData diagnosticData, TimestampWrapper timestampWrapper) {
        assertNotNull(timestampWrapper.getProductionTime());
        assertTrue(timestampWrapper.isMessageImprintDataFound());
        assertTrue(timestampWrapper.isMessageImprintDataIntact());
        assertTrue(timestampWrapper.isSignatureIntact());
        assertTrue(timestampWrapper.isSignatureValid());

        List<XmlDigestMatcher> digestMatchers = timestampWrapper.getDigestMatchers();
        for (XmlDigestMatcher xmlDigestMatcher : digestMatchers) {
            assertTrue(xmlDigestMatcher.isDataFound());
            assertTrue(xmlDigestMatcher.isDataIntact());
        }
        if (TimestampType.ARCHIVE_TIMESTAMP.equals(timestampWrapper.getType())) {
            assertNotNull(timestampWrapper.getArchiveTimestampType());
        }

        assertTrue(timestampWrapper.isSigningCertificateIdentified());
        assertTrue(timestampWrapper.isSigningCertificateReferencePresent());
        // signing-certificate reference is not unique

        if (timestampWrapper.isTSAGeneralNamePresent()) {
            assertTrue(timestampWrapper.isTSAGeneralNameMatch());
            assertTrue(timestampWrapper.isTSAGeneralNameOrderMatch());
        }

        CertificateRefWrapper signingCertificateReference = timestampWrapper.getSigningCertificateReference();
        assertNotNull(signingCertificateReference);
        assertTrue(signingCertificateReference.isDigestValuePresent());
        assertTrue(signingCertificateReference.isDigestValueMatch());
        if (signingCertificateReference.isIssuerSerialPresent()) {
            assertTrue(signingCertificateReference.isIssuerSerialMatch());
        }

        CertificateWrapper signingCertificate = timestampWrapper.getSigningCertificate();
        assertNotNull(signingCertificate);
        String signingCertificateId = signingCertificate.getId();
        String certificateDN = diagnosticData.getCertificateDN(signingCertificateId);
        String certificateSerialNumber = diagnosticData.getCertificateSerialNumber(signingCertificateId);
        assertEquals(signingCertificate.getCertificateDN(), certificateDN);
        assertEquals(signingCertificate.getSerialNumber(), certificateSerialNumber);

        assertTrue(Utils.isCollectionEmpty(timestampWrapper.foundCertificates()
                .getOrphanCertificatesByRefOrigin(CertificateRefOrigin.SIGNING_CERTIFICATE)));

        assertTrue(Utils.isCollectionNotEmpty(timestampWrapper.getTimestampedObjects()));

        if (timestampWrapper.getType().isContentTimestamp() || timestampWrapper.getType().isArchivalTimestamp() ||
                timestampWrapper.getType().isDocumentTimestamp() || timestampWrapper.getType().isContainerTimestamp()) {
            assertTrue(Utils.isCollectionNotEmpty(timestampWrapper.getTimestampScopes()));
        } else if (timestampWrapper.getType().isEvidenceRecordTimestamp()) {
            assertTrue(Utils.isCollectionNotEmpty(timestampWrapper.getTimestampScopes()));
        } else {
            assertFalse(Utils.isCollectionNotEmpty(timestampWrapper.getTimestampScopes()));
        }
    }

}
