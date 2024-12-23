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
package eu.europa.esig.dss.asic.cades.validation.evidencerecord;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.EvidenceRecordWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTimestampedObject;
import eu.europa.esig.dss.enumerations.TimestampedObjectType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.ExternalResourcesOCSPSource;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.validationreport.enums.ObjectType;
import eu.europa.esig.validationreport.enums.TypeOfProof;
import eu.europa.esig.validationreport.jaxb.POEType;
import eu.europa.esig.validationreport.jaxb.VOReferenceType;
import eu.europa.esig.validationreport.jaxb.ValidationObjectType;
import eu.europa.esig.validationreport.jaxb.ValidationTimeInfoType;

import java.util.List;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ASiCEWithCAdESLevelBWithEvidenceRecordAdditionalFilesValidationTest extends AbstractASiCEWithCAdESWithEvidenceRecordTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new FileDocument("src/test/resources/validation/evidencerecord/cades-b-with-er-additional-files.asice");
    }

    @Override
    protected CertificateSource getTrustedCertificateSource() {
        CommonTrustedCertificateSource trustedCertificateSource = new CommonTrustedCertificateSource();
        trustedCertificateSource.addCertificate(DSSUtils.loadCertificateFromBase64EncodedString("MIIFwzCCA6ugAwIBAgIUCn6m30tEntpqJIWe5rgV0xZ/u7EwDQYJKoZIhvcNAQELBQAwRjELMAkGA1UEBhMCTFUxFjAUBgNVBAoMDUx1eFRydXN0IFMuQS4xHzAdBgNVBAMMFkx1eFRydXN0IEdsb2JhbCBSb290IDIwHhcNMTUwMzA1MTMyMTU3WhcNMzUwMzA1MTMyMTU3WjBGMQswCQYDVQQGEwJMVTEWMBQGA1UECgwNTHV4VHJ1c3QgUy5BLjEfMB0GA1UEAwwWTHV4VHJ1c3QgR2xvYmFsIFJvb3QgMjCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBANeFl78RmOnwYoNMPIf5U2o3C/IPPIfOb9wmKb3FibrJgz337spbxm1Jc7TJRqMbNBM/wYlFV/TZsfs2ZUv7COJIcRHIbjuend+JZTemhfY7RBi2xjcwYkSSl2l9QjAk5A0MiWtj3sXh306pFGxT4GHO9hcvHTy95iJMHZP1EMShduxq3sVs35a0VkBCwGKSMKEtFZSg0iAGCW5qbeXrt77U8PEVfIvmTroTzEsnXpk8F12PgX8zPU/TPxvsXD/wPEx1bvKm1Z3aLQdjAsZy6ZS8TEmVT4hSyNvoaYL4zDRbIvCGp4m9SAptZoFtyMhk+wHh9OHe2Z7d21vUKpkmFRseTJIpgp7VkoGSQXAZ96Tlk0u8d2cx3Rz9MXANF5kM+Qw5GSoXtTBxVdUPrljhPS80m8+f9niFwpN6cj5mj5wWEWCPnolvZ77gR1o7DJpni89Gxq44o/KnvObWhWszJHAiS8sIm7vI+AIpHb4gDEa/a4ebsypmQjVGbKq6rfmYe+lQVRQxv7HaLe2ArWgk+2mr2HETMOZns4dA/Yl+8kPREd8vZS9kzl8UubG/Mb2HeFpZZYiq/FkySIbWTLkpS5XTdvN3JW1CHDiDTf2jX5t/Lax5Gw5CMZdjpPuKadUiDTSQMC6otOBttpSsvItO13D8xTiOZCXhTTmQzsmHhFhxAgMBAAGjgagwgaUwDwYDVR0TAQH/BAUwAwEB/zBCBgNVHSAEOzA5MDcGByuBKwEBAQowLDAqBggrBgEFBQcCARYeaHR0cHM6Ly9yZXBvc2l0b3J5Lmx1eHRydXN0Lmx1MA4GA1UdDwEB/wQEAwIBBjAfBgNVHSMEGDAWgBT/GCh2+UgFLKGu8SsbK7JT+Et8szAdBgNVHQ4EFgQU/xgodvlIBSyhrvErGyuyU/hLfLMwDQYJKoZIhvcNAQELBQADggIBAGoZFO1uecEsh9QNcH7X9njJCwROxLHOk3D+sFTAMs2ZMGQXvw/l4jP9BzZAcg4atmpZ1gDlaCDdLnINH2pkMSCEfUmmWjfrRcmF9dTHF5kH5ptV5AzoqbTOjFu1EVzPig4N1qx3gf4ynCSecs5U89BvolbW7MM3LGVYvlcAGvI1+ut7MV3CwRI9loGIlonBWVx65n9wNOeD4rHh4bhY79SV5GCc8JaXcozrhAIuZY+kt9J/Z93I055cqqmkoCUUBpvsT34tC38ddfEz2O3OuHVtPlu5mB0xDVbYQw8wkbIEa91WvpWAVWe+2M2D2RjuLg+GLZKecBPs3lHJQ3gCpU3I+V/EkVhGFndadKpAvAefMLmx9xIX3eP/JEAdemrRTxgKqpAd60Ae36EeRJIQmvKN4dFLRp7oRUKX6kWZ8+xm1QL68qZKJKrezrnK+T+Tb/mjuuqlPpmt/f97mfVl7vBZKGfXkJWkE4SphMHozs51k2MavDzq1WQfLSoSOcbDWjLtR5EWDrw4wVDej8oqkDQc7kGUnF4ZLvhFSZl0kbAEb+MEWrGrKqv+x9CWttrhSmQGbmBNvUJO/3jaJMobtNeWOWyu8Q6qp31IiyBMz2TWuJdGsE7RKlY6oJO9r4Ak4Ap+58rVyuiFVdw2KuGUaJPHZnJED4AhMmwlxyOAgwrr"));
        trustedCertificateSource.addCertificate(DSSUtils.loadCertificateFromBase64EncodedString("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"));
        trustedCertificateSource.addCertificate(DSSUtils.loadCertificateFromBase64EncodedString("MIIERzCCA86gAwIBAgIUEFsEYuhn+NxO8EbEovbXNQS+YskwCgYIKoZIzj0EAwMwgbsxCzAJBgNVBAYTAkJFMREwDwYDVQQHDAhCcnVzc2VsczEwMC4GA1UECgwnS2luZ2RvbSBvZiBCZWxnaXVtIC0gRmVkZXJhbCBHb3Zlcm5tZW50MT8wPQYDVQQLDDZRVFNQOiBGUFMgUG9saWN5IGFuZCBTdXBwb3J0IC0gQk9TQSAoTlRSQkUtMDY3MTUxNjY0NykxDzANBgNVBAUTBjIwMjEwMTEVMBMGA1UEAwwMVGltZXN0YW1wIENBMB4XDTIxMDMxNjA5NDAyNFoXDTI3MDMxNjA5NDAyNFowgb0xCzAJBgNVBAYTAkJFMREwDwYDVQQHDAhCcnVzc2VsczEwMC4GA1UECgwnS2luZ2RvbSBvZiBCZWxnaXVtIC0gRmVkZXJhbCBHb3Zlcm5tZW50MT8wPQYDVQQLDDZRVFNQOiBGUFMgUG9saWN5IGFuZCBTdXBwb3J0IC0gQk9TQSAoTlRSQkUtMDY3MTUxNjY0NykxDzANBgNVBAUTBjIwMjEwMjEXMBUGA1UEAwwOVGltZXN0YW1wIFVuaXQwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQgW045n8P+kf/32AZ+HfDC+it91DWvUg1VuyLBPXklBXS2aJ3SoWleLm9dbBIR+dN2VnGNpxJeWJwkrLV6ed6Co4IBqjCCAaYwDAYDVR0TAQH/BAIwADAfBgNVHSMEGDAWgBTgThvTdU21h04CtvqpWmPMPKqYmTB7BggrBgEFBQcBAQRvMG0wOgYIKwYBBQUHMAKGLmh0dHA6Ly9jcnQuZWlkcGtpLmJlbGdpdW0uYmUvdHMvdHNjYTIwMjEwMS5jcnQwLwYIKwYBBQUHMAGGI2h0dHA6Ly9vY3NwLmVpZHBraS5iZWxnaXVtLmJlL2VpZC8wMFYGA1UdIARPME0wQAYHYDgNBgOHaDA1MDMGCCsGAQUFBwIBFidodHRwczovL3JlcG9zaXRvcnkuZWlkcGtpLmJlbGdpdW0uYmUvdHMwCQYHBACL7EABATAWBgNVHSUBAf8EDDAKBggrBgEFBQcDCDAYBggrBgEFBQcBAwQMMAowCAYGBACORgEBMD8GA1UdHwQ4MDYwNKAyoDCGLmh0dHA6Ly9jcmwuZWlkcGtpLmJlbGdpdW0uYmUvdHMvdHNjYTIwMjEwMS5jcmwwHQYDVR0OBBYEFCz5Qqc7x2eYCEXyMH4p6AYCG5EQMA4GA1UdDwEB/wQEAwIHgDAKBggqhkjOPQQDAwNnADBkAjB0oreRkNZ7AxdtICH6lkW8nERAwDPWP8w5BUSZL8sJ5KrootY9gevtIn1+FbFTJRACMAi8hy0yn0pO0Pl4wzCmgcRhpaPmsmeJ8j3bo573kh1MK4psbY2Q3swkNu+8QWmi3g=="));
        return trustedCertificateSource;
    }

    @Override
    protected CertificateVerifier getOfflineCertificateVerifier() {
        CertificateVerifier certificateVerifier = super.getOfflineCertificateVerifier();
        ExternalResourcesOCSPSource ocspSource = new ExternalResourcesOCSPSource(
                new InMemoryDocument(Utils.fromBase64("MIIEAQoBAKCCA/owggP2BgkrBgEFBQcwAQEEggPnMIID4zCByKIWBBTEJLuX2+0XHZOLhVYAsX+aNvoZ0xgPMjAyMzEyMDQxMjIyMTFaMIGcMIGZME0wCQYFKw4DAhoFAAQUTTkwD3yuwf+FIqy4qwf8fKdxdhUEFC6giLALDWKJ7B0/1J/MkkSOSGlGAhQFwx08ZmVl44YrA60vxFUleAW0uIAAGA8yMDIzMTIwNDEyMjIxMVqgERgPMjAyMzEyMDQxMjIzMTBaoSIwIDAeBgkrBgEFBQcwAQYEERgPMjAyMDA2MDMxMDAxMzFaMAoGCCqGSM49BAMCA0cAMEQCICj+GqzWnVJayYaSWFweTiqA94aXtrTgYmP523otqL7BAiACPrvrmPGVfegjUflsDyWHL5e9xqSBZhKSuSUR78kdWKCCAr8wggK7MIICtzCCAj2gAwIBAgIUWEyep39OVbznsVv+UTnO8LYcW0AwCgYIKoZIzj0EAwMwgeAxCzAJBgNVBAYTAkJFMREwDwYDVQQHDAhCcnVzc2VsczEwMC4GA1UECgwnS2luZ2RvbSBvZiBCZWxnaXVtIC0gRmVkZXJhbCBHb3Zlcm5tZW50MTYwNAYDVQQLDC1GUFMgSG9tZSBBZmZhaXJzIC0gQklLLUdDSSAoTlRSQkUtMDM2MjQ3NTUzOCkxOTA3BgNVBAsMMEZQUyBQb2xpY3kgYW5kIFN1cHBvcnQgLSBCT1NBIChOVFJCRS0wNjcxNTE2NjQ3KTEZMBcGA1UEAwwQQmVsZ2l1bSBSb290IENBNjAeFw0yMzExMDcxMTM5MDVaFw0yNTExMDYxMTM5MDVaMCwxCzAJBgNVBAYTAkJFMR0wGwYDVQQDDBRCUkNBNiBPQ1NQIFJlc3BvbmRlcjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABK6az2VXciTnSa9YzpYInWPqOrOm6eCF+i/554OCx2rJX/QVy7WceuLq03DOMwjf8y9znRwX7fLeZIFjIIUct76jgYcwgYQwDAYDVR0TAQH/BAIwADAfBgNVHSMEGDAWgBQuoIiwCw1iiewdP9SfzJJEjkhpRjAPBgkrBgEFBQcwAQUEAgUAMBMGA1UdJQQMMAoGCCsGAQUFBwMJMB0GA1UdDgQWBBTEJLuX2+0XHZOLhVYAsX+aNvoZ0zAOBgNVHQ8BAf8EBAMCB4AwCgYIKoZIzj0EAwMDaAAwZQIwTyGR2VdPeiciyQnPHghcNdYSWomjFoobQ7+WaMTeDZteDLuMvaiKj2SVruATVMo7AjEA1LzW/3R59QBUltDU65ZAv+TZlzD0Ng5Kr0V7Gbb1jb6E+YnauAhMlN8bmpdIW2HV")),
                new InMemoryDocument(Utils.fromBase64("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<"))
        );
        certificateVerifier.setOcspSource(ocspSource);
        return certificateVerifier;
    }

    @Override
    protected boolean allArchiveDataObjectsProvidedToValidation() {
        return false;
    }

    @Override
    protected int getNumberOfExpectedEvidenceScopes() {
        return 2; // signature + 2 data files
    }

    @Override
    protected void checkEvidenceRecordDigestMatchers(DiagnosticData diagnosticData) {
        EvidenceRecordWrapper evidenceRecord = diagnosticData.getEvidenceRecords().get(0);

        int foundRefsCounter = 0;
        int validRefsCounter = 0;
        int invalidRefsCounter = 0;
        List<XmlDigestMatcher> digestMatcherList = evidenceRecord.getDigestMatchers();
        assertEquals(4, Utils.collectionSize(digestMatcherList));
        for (XmlDigestMatcher digestMatcher : digestMatcherList) {
            if (digestMatcher.isDataFound()) {
                assertNotNull(digestMatcher.getUri());
                assertNotNull(digestMatcher.getDocumentName());
                ++foundRefsCounter;
            }
            if (digestMatcher.isDataIntact()) {
                ++validRefsCounter;
            } else {
                ++invalidRefsCounter;
            }
        }
        assertEquals(2, foundRefsCounter);
        assertEquals(2, validRefsCounter);
        assertEquals(2, invalidRefsCounter);
    }

    @Override
    protected void checkEvidenceRecordTimestampedReferences(DiagnosticData diagnosticData) {
        List<SignatureWrapper> signatures = diagnosticData.getSignatures();

        List<EvidenceRecordWrapper> evidenceRecords = diagnosticData.getEvidenceRecords();
        EvidenceRecordWrapper evidenceRecord = evidenceRecords.get(0);
        List<XmlTimestampedObject> coveredObjects = evidenceRecord.getCoveredObjects();
        assertTrue(Utils.isCollectionNotEmpty(coveredObjects));

        assertEquals(Utils.collectionSize(signatures), coveredObjects.stream()
                .filter(r -> TimestampedObjectType.SIGNATURE == r.getCategory()).count());
        assertTrue(Utils.isCollectionNotEmpty(coveredObjects.stream()
                .filter(r -> TimestampedObjectType.SIGNED_DATA == r.getCategory()).collect(Collectors.toList())));

        assertEquals(Utils.collectionSize(signatures), Utils.collectionSize(evidenceRecord.getCoveredSignatures()));
        if (Utils.isCollectionNotEmpty(signatures)) {
            assertTrue(Utils.isCollectionNotEmpty(evidenceRecord.getCoveredCertificates()));
            assertFalse(Utils.isCollectionNotEmpty(evidenceRecord.getCoveredRevocations()));
            assertFalse(Utils.isCollectionNotEmpty(evidenceRecord.getCoveredTimestamps()));
        }
        assertTrue(Utils.isCollectionNotEmpty(evidenceRecord.getCoveredSignedData()));
    }

    @Override
    protected void validateTimeInfo(ValidationTimeInfoType validationTimeInfo) {
        super.validateTimeInfo(validationTimeInfo);

        assertNotNull(validationTimeInfo.getValidationTime());

        POEType bestSignatureTime = validationTimeInfo.getBestSignatureTime();
        assertNotNull(bestSignatureTime);
        assertNotNull(bestSignatureTime.getPOETime());
        assertEquals(TypeOfProof.VALIDATION, bestSignatureTime.getTypeOfProof());

        VOReferenceType poeObject = bestSignatureTime.getPOEObject();
        assertNotNull(poeObject);
        assertEquals(1, poeObject.getVOReference().size());

        ValidationObjectType validationObject = (ValidationObjectType) poeObject.getVOReference().get(0);
        assertNotNull(validationObject.getId());
        assertEquals(ObjectType.EVIDENCE_RECORD, validationObject.getObjectType());
    }

}
