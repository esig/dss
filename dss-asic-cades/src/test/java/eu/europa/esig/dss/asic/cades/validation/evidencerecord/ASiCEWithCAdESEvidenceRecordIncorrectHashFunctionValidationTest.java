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
package eu.europa.esig.dss.asic.cades.validation.evidencerecord;

import eu.europa.esig.dss.asic.common.validation.AbstractASiCWithEvidenceRecordTestValidation;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.EvidenceRecordWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignatureScope;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.enumerations.EvidenceRecordTimestampType;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.enumerations.TimestampedObjectType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.ReferenceValidation;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.simplereport.jaxb.XmlEvidenceRecord;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;
import eu.europa.esig.dss.spi.x509.evidencerecord.EvidenceRecord;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ASiCEWithCAdESEvidenceRecordIncorrectHashFunctionValidationTest extends AbstractASiCWithEvidenceRecordTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new FileDocument("src/test/resources/validation/evidencerecord/er-asn1-incorrect-hash.asice");
    }

    @Override
    protected CertificateSource getTrustedCertificateSource() {
        CommonTrustedCertificateSource trustedCertificateSource = new CommonTrustedCertificateSource();
        trustedCertificateSource.addCertificate(DSSUtils.loadCertificateFromBase64EncodedString("MIIFRzCCA3ugAwIBAgIBBjBBBgkqhkiG9w0BAQowNKAPMA0GCWCGSAFlAwQCAQUAoRwwGgYJKoZIhvcNAQEIMA0GCWCGSAFlAwQCAQUAogMCASAwVTELMAkGA1UEBhMCREUxJTAjBgNVBAoMHGV4Y2VldCBTZWN1cmUgU29sdXRpb25zIEdtYkgxHzAdBgNVBAMMFmV4Y2VldCB0cnVzdGNlbnRlciBDQTIwHhcNMTYxMDEzMDk0ODQ0WhcNMjExMDEyMDk0ODQzWjBlMQswCQYDVQQGEwJERTElMCMGA1UECgwcZXhjZWV0IFNlY3VyZSBTb2x1dGlvbnMgR21iSDEXMBUGA1UEYQwOTlRSREUtSFJCNzg3NzAxFjAUBgNVBAMMDWV4Y2VldCBUU0EgMDQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCBTsjBR68tKQQ6LPisgVvwaxID784nlmspjHc9Wl6vq7Smvk5a4jZ6GxccJL/rwCBLTs0z7zjeo9aEyzIe9YlcyeRyNp+QXfPqVeeXn4WAXM1hYaUt4LHrytkOqwj1sfwPx4TrES63Ot9h6pXBVFdkbYg8gsRD1YsryEXqwKCTnlLlDzbkjOy0a6W+ZzsEJiYtuOnfW64xDEKqgCutVmsPPT5NCnm+H7q8xqwXa6s0alEDeLnn0W5bjltQKqVTtYDfERN2Jovzzt+gWiX7XUBkGCvJU+MFErDzI522clrsqwhzQteqP4l+Haf7IPeBjzDT/x6o6qYBmRlupRYzQ0yZAgMBAAGjggEoMIIBJDAdBgNVHQ4EFgQUAF3jsWWyWkGeoGRYCMMr67aW7uIwfQYDVR0jBHYwdIAUo7AmghzxQnnQGqwp3XwFlw/e3ZGhWaRXMFUxCzAJBgNVBAYTAkRFMSUwIwYDVQQKDBxleGNlZXQgU2VjdXJlIFNvbHV0aW9ucyBHbWJIMR8wHQYDVQQDDBZleGNlZXQgdHJ1c3RjZW50ZXIgQ0EyggEBMDkGCCsGAQUFBwEBBC0wKzApBggrBgEFBQcwAYYdaHR0cDovL29jc3AuZXhjZWV0LmNsb3VkL29jc3AwDgYDVR0PAQH/BAQDAgbAMBMGA1UdIAQMMAowCAYGBACPegECMAwGA1UdEwEB/wQCMAAwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwQQYJKoZIhvcNAQEKMDSgDzANBglghkgBZQMEAgEFAKEcMBoGCSqGSIb3DQEBCDANBglghkgBZQMEAgEFAKIDAgEgA4IBgQB6KlKklsZohZ4oH5gd6ZwL1K0ukFXsVaZvjSJGvrgNtdYQZhDpjsEWd5teWOP50DZKLE4gldlF2ZIAA5TNh09+60UXfUedRA9WAbYo7R3bXmAjEYTVMyuBHQSPApmXYNJfpQMq0E7wMwhhftJS3UESeAhljAuvlh+LHD+j+Rkf+FYNWwpBcscDIq7SYdRGU+xMqQZyeh246vycgvYyrYRw/4BEmS7erpqnkwTgWUZ9NQ7nxkUHEhTbNbuoyJ999O2m9nI0j5T2tJsWG7iRgcK5haJwugBBJ+nGSzoOPAdGLoHsKTDBZ5Jx2i5avpjfs6FVz6xJFI5ZqFzpd+T+TmSxKIHrvgwCMJDXY+dISoFqT6rGctGpyh4nMJqJLmtJssqLQfVaEjHL8t79DlJ/OPmkZSWJVdK5BfpCR264VkTrY3rJAfhbLWfWHCYL+wNWJknbAyw0yHYngto+DLEkrI9OrN7hlKjn3wUXHNKevgxVXYGOyQGdOsV5SuB/+0ErGaY="));
        trustedCertificateSource.addCertificate(DSSUtils.loadCertificateFromBase64EncodedString("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"));
        return trustedCertificateSource;
    }

    @Override
    protected void checkDetachedEvidenceRecords(List<EvidenceRecord> detachedEvidenceRecords) {
        assertEquals(1, detachedEvidenceRecords.size());

        EvidenceRecord evidenceRecord = detachedEvidenceRecords.get(0);
        List<ReferenceValidation> referenceValidationList = evidenceRecord.getReferenceValidation();
        assertEquals(2, referenceValidationList.size());

        ReferenceValidation referenceValidation = referenceValidationList.get(0);
        assertEquals(DigestMatcherType.EVIDENCE_RECORD_ARCHIVE_OBJECT, referenceValidation.getType());
        assertNotNull(referenceValidation.getDocumentName());
        assertTrue(referenceValidation.isFound());
        assertTrue(referenceValidation.isIntact());

        List<TimestampToken> timestamps = evidenceRecord.getTimestamps();
        assertEquals(3, timestamps.size());

        boolean firstTstFound = false;
        boolean archiveTstRefreshRefFound = false;
        boolean archiveTstSequenceRefFound = false;

        for (TimestampToken timestampToken : timestamps) {
            assertNotNull(timestampToken.getTimeStampType());
            assertNotNull(timestampToken.getArchiveTimestampType());
            assertNotNull(timestampToken.getEvidenceRecordTimestampType());

            assertTrue(timestampToken.isProcessed());

            List<ReferenceValidation> tstReferenceValidationList = timestampToken.getReferenceValidations();
            long coveredTimestamps = timestampToken.getTimestampedReferences().stream()
                    .filter(r -> TimestampedObjectType.TIMESTAMP == r.getCategory()).count();
            int validRefsCounter = 0;
            int invalidRefsCounter = 0;
            int orphanRefsCounter = 0;
            for (ReferenceValidation tstReferenceValidation : tstReferenceValidationList) {
                if (DigestMatcherType.EVIDENCE_RECORD_ARCHIVE_OBJECT == tstReferenceValidation.getType()) {
                    if (tstReferenceValidation.isFound() && tstReferenceValidation.isIntact()) {
                        ++validRefsCounter;
                    } else if (tstReferenceValidation.isFound() && !tstReferenceValidation.isIntact()) {
                        ++invalidRefsCounter;
                    }
                    archiveTstSequenceRefFound = true;
                } else if (DigestMatcherType.EVIDENCE_RECORD_ORPHAN_REFERENCE == tstReferenceValidation.getType()) {
                    ++orphanRefsCounter;
                } else if (DigestMatcherType.EVIDENCE_RECORD_ARCHIVE_TIME_STAMP == tstReferenceValidation.getType()) {
                    assertEquals(1, coveredTimestamps);
                    assertTrue(tstReferenceValidation.isFound());
                    assertFalse(tstReferenceValidation.isIntact());
                    archiveTstRefreshRefFound = true;
                }
            }

            if (coveredTimestamps == 0) {
                assertTrue(timestampToken.isMessageImprintDataFound());
                assertTrue(timestampToken.isMessageImprintDataIntact());
                assertEquals(EvidenceRecordTimestampType.ARCHIVE_TIMESTAMP, timestampToken.getEvidenceRecordTimestampType());

                assertEquals(0, validRefsCounter);
                assertEquals(0, invalidRefsCounter);
                assertEquals(0, orphanRefsCounter);

                firstTstFound = true;

            } else if (coveredTimestamps == 1) {
                assertTrue(timestampToken.isMessageImprintDataFound());
                assertFalse(timestampToken.isMessageImprintDataIntact());
                assertEquals(EvidenceRecordTimestampType.TIMESTAMP_RENEWAL_ARCHIVE_TIMESTAMP, timestampToken.getEvidenceRecordTimestampType());

                assertEquals(0, validRefsCounter);
                assertEquals(0, invalidRefsCounter);
                assertEquals(0, orphanRefsCounter);

            } else if (coveredTimestamps == 2) {
                assertTrue(timestampToken.isMessageImprintDataFound());
                assertTrue(timestampToken.isMessageImprintDataIntact());
                assertEquals(EvidenceRecordTimestampType.HASH_TREE_RENEWAL_ARCHIVE_TIMESTAMP, timestampToken.getEvidenceRecordTimestampType());

                assertEquals(1, validRefsCounter);
                assertEquals(0, invalidRefsCounter);
                assertEquals(1, orphanRefsCounter);
            }

        }

        assertTrue(firstTstFound);
        assertTrue(archiveTstRefreshRefFound);
        assertTrue(archiveTstSequenceRefFound);
    }

    @Override
    protected void checkEvidenceRecordTimestamps(DiagnosticData diagnosticData) {
        List<EvidenceRecordWrapper> evidenceRecords = diagnosticData.getEvidenceRecords();
        EvidenceRecordWrapper evidenceRecordWrapper = evidenceRecords.get(0);
        List<XmlSignatureScope> evidenceRecordScopes = evidenceRecordWrapper.getEvidenceRecordScopes();
        assertEquals(2, evidenceRecordScopes.size());

        assertEquals(3, diagnosticData.getTimestampList().size());

        List<TimestampWrapper> timestampList = evidenceRecordWrapper.getTimestampList();
        assertEquals(3, timestampList.size());

        boolean firstTstFound = false;
        boolean archiveTstRefreshRefFound = false;
        boolean archiveTstSequenceRefFound = false;

        for (TimestampWrapper timestampWrapper : timestampList) {
            assertNotNull(timestampWrapper.getType());
            assertNotNull(timestampWrapper.getArchiveTimestampType());
            assertNotNull(timestampWrapper.getEvidenceRecordTimestampType());

            List<XmlDigestMatcher> digestMatchers = timestampWrapper.getDigestMatchers();
            long coveredTimestamps = timestampWrapper.getTimestampedTimestamps().size();
            int validRefsCounter = 0;
            int invalidRefsCounter = 0;
            int orphanRefsCounter = 0;
            for (XmlDigestMatcher digestMatcher : digestMatchers) {
                if (DigestMatcherType.EVIDENCE_RECORD_ARCHIVE_OBJECT == digestMatcher.getType()) {
                    if (digestMatcher.isDataFound() && digestMatcher.isDataIntact()) {
                        ++validRefsCounter;
                    } else if (digestMatcher.isDataFound() && !digestMatcher.isDataIntact()) {
                        ++invalidRefsCounter;
                    }
                    archiveTstSequenceRefFound = true;
                } else if (DigestMatcherType.EVIDENCE_RECORD_ORPHAN_REFERENCE == digestMatcher.getType()) {
                    ++orphanRefsCounter;
                } else if (DigestMatcherType.EVIDENCE_RECORD_ARCHIVE_TIME_STAMP == digestMatcher.getType()) {
                    assertEquals(1, coveredTimestamps);
                    assertTrue(digestMatcher.isDataFound());
                    assertFalse(digestMatcher.isDataIntact());
                    archiveTstRefreshRefFound = true;
                }
            }

            if (coveredTimestamps == 0) {
                assertTrue(timestampWrapper.isMessageImprintDataFound());
                assertTrue(timestampWrapper.isMessageImprintDataIntact());
                assertTrue(timestampWrapper.isSignatureIntact());
                assertTrue(timestampWrapper.isSignatureValid());
                assertEquals(EvidenceRecordTimestampType.ARCHIVE_TIMESTAMP, timestampWrapper.getEvidenceRecordTimestampType());

                assertEquals(0, validRefsCounter);
                assertEquals(0, invalidRefsCounter);
                assertEquals(0, orphanRefsCounter);

                firstTstFound = true;

            } else if (coveredTimestamps == 1) {
                assertTrue(timestampWrapper.isMessageImprintDataFound());
                assertFalse(timestampWrapper.isMessageImprintDataIntact());
                assertTrue(timestampWrapper.isSignatureIntact());
                assertFalse(timestampWrapper.isSignatureValid());
                assertEquals(EvidenceRecordTimestampType.TIMESTAMP_RENEWAL_ARCHIVE_TIMESTAMP, timestampWrapper.getEvidenceRecordTimestampType());

                assertEquals(0, validRefsCounter);
                assertEquals(0, invalidRefsCounter);
                assertEquals(0, orphanRefsCounter);

            } else if (coveredTimestamps == 2) {
                assertTrue(timestampWrapper.isMessageImprintDataFound());
                assertTrue(timestampWrapper.isMessageImprintDataIntact());
                assertTrue(timestampWrapper.isSignatureIntact());
                assertTrue(timestampWrapper.isSignatureValid());
                assertEquals(EvidenceRecordTimestampType.HASH_TREE_RENEWAL_ARCHIVE_TIMESTAMP, timestampWrapper.getEvidenceRecordTimestampType());

                assertEquals(1, validRefsCounter);
                assertEquals(0, invalidRefsCounter);
                assertEquals(1, orphanRefsCounter);
            }

        }

        assertTrue(firstTstFound);
        assertTrue(archiveTstRefreshRefFound);
        assertTrue(archiveTstSequenceRefFound);
    }

    @Override
    protected void verifySimpleReport(SimpleReport simpleReport) {
        XmlEvidenceRecord evidenceRecord = simpleReport.getEvidenceRecordById(simpleReport.getFirstEvidenceRecordId());
        assertNotNull(evidenceRecord);
        assertEquals(Indication.FAILED, evidenceRecord.getIndication());
        assertEquals(SubIndication.HASH_FAILURE, evidenceRecord.getSubIndication());
    }

}
