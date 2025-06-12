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
package eu.europa.esig.dss.asic.xades.preservation.container;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.EvidenceRecordWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlManifestFile;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.EvidenceRecordTypeEnum;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.simplereport.jaxb.XmlEvidenceRecord;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.utils.Utils;

import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class ASiCEWithXAdESERAddContainerASN1EvidenceRecordTest extends AbstractASiCWithXAdESTestAddContainerEvidenceRecord {

    @Override
    protected List<DSSDocument> getDocumentsToPreserve() {
        return Collections.singletonList(new FileDocument("src/test/resources/signable/asic_xades_er.sce"));
    }

    @Override
    protected DSSDocument getEvidenceRecordDocument() {
        return new FileDocument("src/test/resources/validation/evidencerecord/incorporation/evidence-record-asic_xades_er-sce.ers");
    }

    @Override
    protected CertificateSource getTrustedCertificateSource() {
        CommonTrustedCertificateSource trustedCertificateSource = new CommonTrustedCertificateSource();
        trustedCertificateSource.addCertificate(DSSUtils.loadCertificateFromBase64EncodedString("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"));
        trustedCertificateSource.addCertificate(DSSUtils.loadCertificateFromBase64EncodedString("MIIHsTCCBZmgAwIBAgIQFb7EwJjBvmNfnBsJTqJLFzANBgkqhkiG9w0BAQsFADBdMQswCQYDVQQGEwJFUzEUMBIGA1UECgwLSVpFTlBFIFMuQS4xGDAWBgNVBGEMD1ZBVEVTLUEwMTMzNzI2MDEeMBwGA1UEAwwVU1VCQ0EgUUMgSVpFTlBFIC0gVFNBMB4XDTIwMTAzMDEzNTQxNloXDTI1MTAzMDEzNTQxNlowVjELMAkGA1UEBhMCRVMxFDASBgNVBAoMC0laRU5QRSBTLkEuMRgwFgYDVQRhDA9WQVRFUy1BMDEzMzcyNjAxFzAVBgNVBAMMDnRzYS5pemVucGUuY29tMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAyDsYtF0sg61SkDg4G7kjy0lgH9W3E5LlizquTp6Gb5xudP910ANsLRr342rEj5gKQUa8pUg7DU1rjFTjItUqRvNgakQ6+W07zv53H99Zw4fn5hziJZdwId5pyGatcCoO/7XCtgZVAFznA9wI8BRjepXT3AIgXHerFIULBb15KhJoAU+MHwnEthZp3mi5zVrxaYYU9j6Hh9uSV5kXHjlURUs4PwUlx0yWggXVpbssAwSu+0GvvVIp4CPvhE3W73ycfeV0NiihOquRsJuxAvZDaeI7cX5SmYZ5lh4rBX2r5H+5qNgYBK736cII9djeeSJS/Db4vkifbIamAxfUFrf1Ot52QDO3CFHNJDAcWhOCRnDV5K8Tvgzh2lQNL/OuJ3uxUopyNhw5CKsVGD/81pA6RAfPnYzKgjdd1hIlt1991CAGSJWUA4JM2O2XLAXW0q2R3ngMWLiSzlGzEXcXiALBrFb47fYg4GUF48Nqa/tKt+nxs9eyI3wyHS1BELB8UsBwAsVRpPmKkz6KsinVOOAGf46lyDublg0mWPEOdNpQw+YZx6R6524ygcjZSIangmzRIcWtNT7mM/zefZKrCZxO67XktAo+rp37nlOZSsgZQK+81csrRh6Pd27heqCyXHyVO3tGbz53ACBuVeCCA+FqCGTCoNSCxVD0P3j1uj+RkDsCAwEAAaOCAnIwggJuMA4GA1UdDwEB/wQEAwIHgDAWBgNVHSUBAf8EDDAKBggrBgEFBQcDCDAdBgNVHQ4EFgQUbnIDfJ9mea3pa1o7uHE/jW+87cwwHwYDVR0jBBgwFoAU6oRFun9cSfsVC6MPDo2c5D+rosEwggEeBgNVHSAEggEVMIIBETCCAQ0GCSsGAQQB8zkKATCB/zAlBggrBgEFBQcCARYZaHR0cDovL3d3dy5pemVucGUuZXVzL2NwczCB1QYIKwYBBQUHAgIwgcgMgcVLb250c3VsdGEgd3d3Lml6ZW5wZS5ldXMtZW4gYmFsZGludHphayBldGEga29uZGl6aW9hayB6aXVydGFnaXJpYW4gZmlkYXR1IGVkbyBlcmFiaWxpIGF1cnJldGlrIC0gQ29uc3VsdGUgZW4gd3d3Lml6ZW5wZS5ldXMgbG9zIHTDqXJtaW5vcyB5IGNvbmRpY2lvbmVzIGFudGVzIGRlIHV0aWxpemFyIG8gY29uZmlhciBlbiBlbCBjZXJ0aWZpY2FkbzAyBggrBgEFBQcBCwQmMCQwIgYIKwYBBQUHMAOGFmh0dHA6Ly90c2EuaXplbnBlLmV1cy8wdAYIKwYBBQUHAQEEaDBmMGQGCCsGAQUFBzAChlhodHRwOi8vd3d3Lml6ZW5wZS5ldXMvY29udGVuaWRvcy9pbmZvcm1hY2lvbi9jYXNfaXplbnBlL2VzX2Nhcy9hZGp1bnRvcy9TVUJDQV9RQ19UU0EuY3J0MDgGA1UdHwQxMC8wLaAroCmGJ2h0dHA6Ly9jcmwuaXplbnBlLmV1cy9jZ2ktYmluL2l6ZW5wZVRTQTANBgkqhkiG9w0BAQsFAAOCAgEAVXSws6SSgh31G1kYgZYYmdCbhDWA/EDoyl5jlT8xJVVLndVldjI2wqC3xcYgAArgQK8H84U9RKJUHsq2x66fplAV2vMRoepqAc2S9zGcaXhkew5mNgXQF1pWqVadnuSazUiDAZdJmNnPaefVnIj/gY04c/yxHcVf7IOTnhtMxTayFrIpmN/3x2BUc05UlWmAPw+W+6A1NYBbyuQOt5OpvRU/bOmv+fG3ed/8fdcrSOTBJSA2enu9XeDTs5E9O8TtjZ/2Wk5fPzLwfJphDLOyKMKIkntcvuz+EmlD2ZtOySnB+IWFBw2kANJELpgcOJrBQnyMJ9cqFTA9F91yVM6Dv3dNAFfPCnA/KF3Oa/4+e2PjTtwOTTEbPGFwDPtz+sHBm3RhW1LFGn4+eOmlyhg+iC7x32EmWT2Xb0Qa0wmGfyYJFtfFdgo5EK4VVEytGi+tJPfnLA5uEjGbTovo/Zhc12/2d5nW1KqPfueCLxU9OKZ/8Ua7WehazRtm75h0iowGB5I5z5vwtqbv6n4UN0W4/XZfrepKSTeGMiuZICvMDoc01LqX5OVC0LUrwqJRpKvCf6Z+2wa2YpYaC+k3xsnjkThON6Hdx1wsolPpAt+4BqCuftiYANnzfV2weNbe6pWI/q7tGaqv3a0tmfTZ849stJbxsQDqAZcXNHbHR3ztMj4="));
        return trustedCertificateSource;
    }

    @Override
    protected ASiCContainerType getASiCContainerType() {
        return ASiCContainerType.ASiC_E;
    }

    @Override
    protected EvidenceRecordTypeEnum getEvidenceRecordType() {
        return EvidenceRecordTypeEnum.ASN1_EVIDENCE_RECORD;
    }

    @Override
    protected int getNumberOfExpectedEvidenceScopes() {
        return 2;
    }

    @Override
    protected void checkEvidenceRecordCoverage(DiagnosticData diagnosticData, SignatureWrapper signature) {
        List<EvidenceRecordWrapper> evidenceRecords = signature.getEvidenceRecords();
        assertEquals(2, evidenceRecords.size());

        int xmlERCounter = 0;
        int asn1ERCounter = 0;
        for (EvidenceRecordWrapper evidenceRecord : evidenceRecords) {
            if (EvidenceRecordTypeEnum.XML_EVIDENCE_RECORD == evidenceRecord.getEvidenceRecordType()) {
                assertEquals(1, Utils.collectionSize(evidenceRecord.getEvidenceRecordScopes()));
                assertTrue(Utils.isCollectionNotEmpty(evidenceRecord.getCoveredSignatures()));
                assertTrue(Utils.isCollectionNotEmpty(evidenceRecord.getCoveredSignatures()));
                assertTrue(Utils.isCollectionNotEmpty(evidenceRecord.getCoveredTimestamps()));
                assertTrue(Utils.isCollectionNotEmpty(evidenceRecord.getCoveredCertificates()));
                assertTrue(Utils.isCollectionNotEmpty(evidenceRecord.getCoveredRevocations()));
                assertFalse(Utils.isCollectionNotEmpty(evidenceRecord.getCoveredEvidenceRecords()));
                ++xmlERCounter;

            } else if (EvidenceRecordTypeEnum.ASN1_EVIDENCE_RECORD == evidenceRecord.getEvidenceRecordType()) {
                assertEquals(2, Utils.collectionSize(evidenceRecord.getEvidenceRecordScopes()));
                assertTrue(Utils.isCollectionNotEmpty(evidenceRecord.getCoveredSignatures()));
                assertTrue(Utils.isCollectionNotEmpty(evidenceRecord.getCoveredSignatures()));
                assertTrue(Utils.isCollectionNotEmpty(evidenceRecord.getCoveredTimestamps()));
                assertTrue(Utils.isCollectionNotEmpty(evidenceRecord.getCoveredCertificates()));
                assertTrue(Utils.isCollectionNotEmpty(evidenceRecord.getCoveredRevocations()));
                assertFalse(Utils.isCollectionNotEmpty(evidenceRecord.getCoveredEvidenceRecords()));
                ++asn1ERCounter;
            }
        }
        assertEquals(1, xmlERCounter);
        assertEquals(1, asn1ERCounter);
    }

    @Override
    protected void checkEvidenceRecordTimestamps(DiagnosticData diagnosticData) {
        List<EvidenceRecordWrapper> evidenceRecords = diagnosticData.getEvidenceRecords();
        for (EvidenceRecordWrapper evidenceRecord : evidenceRecords) {
            List<TimestampWrapper> timestamps = evidenceRecord.getTimestampList();
            assertTrue(Utils.isCollectionNotEmpty(timestamps));
            for (TimestampWrapper timestampWrapper : timestamps) {
                assertTrue(timestampWrapper.isMessageImprintDataFound());
                assertTrue(timestampWrapper.isMessageImprintDataIntact());
                assertTrue(timestampWrapper.isSignatureIntact());
                assertTrue(timestampWrapper.isSignatureValid());
            }
        }
    }

    @Override
    protected void checkContainerInfo(DiagnosticData diagnosticData) {
        assertEquals(getASiCContainerType(), diagnosticData.getContainerType());
        int xmlERCounter = 0;
        int asn1ERCounter = 0;
        if (ASiCContainerType.ASiC_E == getASiCContainerType()) {
            List<XmlManifestFile> manifestFiles = diagnosticData.getContainerInfo().getManifestFiles();
            assertTrue(Utils.isCollectionNotEmpty(manifestFiles));
            for (XmlManifestFile xmlManifestFile : manifestFiles) {
                if (xmlManifestFile.getSignatureFilename().equals("META-INF/evidencerecord.xml")) {
                    assertEquals("META-INF/ASiCEvidenceRecordManifest001.xml", xmlManifestFile.getFilename());
                    assertEquals(1, xmlManifestFile.getEntries().size());
                    ++xmlERCounter;
                } else if (xmlManifestFile.getSignatureFilename().equals("META-INF/evidencerecord.ers")) {
                    assertEquals("META-INF/ASiCEvidenceRecordManifest002.xml", xmlManifestFile.getFilename());
                    assertEquals(2, xmlManifestFile.getEntries().size());
                    ++asn1ERCounter;
                }
            }
        }
        assertEquals(1, xmlERCounter);
        assertEquals(1, asn1ERCounter);
    }

    @Override
    protected void verifySimpleReport(SimpleReport simpleReport) {
        int xmlERCounter = 0;
        int asn1ERCounter = 0;
        for (XmlEvidenceRecord evidenceRecord : simpleReport.getSignatureEvidenceRecords(simpleReport.getFirstSignatureId())) {
            if ("META-INF/evidencerecord.xml".equals(evidenceRecord.getFilename())) {
                assertEquals(1, Utils.collectionSize(evidenceRecord.getEvidenceRecordScope()));
                ++xmlERCounter;

            } else if ("META-INF/evidencerecord.ers".equals(evidenceRecord.getFilename())) {
                assertEquals(2, Utils.collectionSize(evidenceRecord.getEvidenceRecordScope()));
                ++asn1ERCounter;
            }
        }
        assertEquals(1, xmlERCounter);
        assertEquals(1, asn1ERCounter);
    }

}
