package eu.europa.esig.dss.xades.validation.evidencerecord;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.EvidenceRecordWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignatureScope;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTimestampedObject;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.enumerations.EvidenceRecordTypeEnum;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SignatureScopeType;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.enumerations.TimestampedObjectType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.simplereport.jaxb.XmlEvidenceRecord;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.validationreport.enums.ObjectType;
import eu.europa.esig.validationreport.enums.TypeOfProof;
import eu.europa.esig.validationreport.jaxb.CryptoInformationType;
import eu.europa.esig.validationreport.jaxb.POEProvisioningType;
import eu.europa.esig.validationreport.jaxb.POEType;
import eu.europa.esig.validationreport.jaxb.SignatureValidationReportType;
import eu.europa.esig.validationreport.jaxb.ValidationObjectListType;
import eu.europa.esig.validationreport.jaxb.ValidationObjectRepresentationType;
import eu.europa.esig.validationreport.jaxb.ValidationObjectType;
import eu.europa.esig.validationreport.jaxb.ValidationReportDataType;
import eu.europa.esig.validationreport.jaxb.ValidationReportType;
import eu.europa.esig.validationreport.jaxb.ValidationStatusType;
import eu.europa.esig.xades.jaxb.xades132.DigestAlgAndValueType;

import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class XAdESLevelLTDetachedWithEmbeddedEvidenceRecordSigNotCoveredTest extends AbstractXAdESWithEvidenceRecordTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new FileDocument("src/test/resources/validation/evidence-record/X-E-ERS-DETACHED-LT-sig-not-covered.xml");
    }

    @Override
    protected List<DSSDocument> getDetachedContents() {
        return Collections.singletonList(new FileDocument("src/test/resources/sample.xml"));
    }

    @Override
    protected CertificateVerifier getOfflineCertificateVerifier() {
        CertificateVerifier certificateVerifier = super.getOfflineCertificateVerifier();
        CommonTrustedCertificateSource trustedCertificateSource = new CommonTrustedCertificateSource();
        trustedCertificateSource.addCertificate(DSSUtils.loadCertificateFromBase64EncodedString("MIIERzCCA86gAwIBAgIUEFsEYuhn+NxO8EbEovbXNQS+YskwCgYIKoZIzj0EAwMwgbsxCzAJBgNVBAYTAkJFMREwDwYDVQQHDAhCcnVzc2VsczEwMC4GA1UECgwnS2luZ2RvbSBvZiBCZWxnaXVtIC0gRmVkZXJhbCBHb3Zlcm5tZW50MT8wPQYDVQQLDDZRVFNQOiBGUFMgUG9saWN5IGFuZCBTdXBwb3J0IC0gQk9TQSAoTlRSQkUtMDY3MTUxNjY0NykxDzANBgNVBAUTBjIwMjEwMTEVMBMGA1UEAwwMVGltZXN0YW1wIENBMB4XDTIxMDMxNjA5NDAyNFoXDTI3MDMxNjA5NDAyNFowgb0xCzAJBgNVBAYTAkJFMREwDwYDVQQHDAhCcnVzc2VsczEwMC4GA1UECgwnS2luZ2RvbSBvZiBCZWxnaXVtIC0gRmVkZXJhbCBHb3Zlcm5tZW50MT8wPQYDVQQLDDZRVFNQOiBGUFMgUG9saWN5IGFuZCBTdXBwb3J0IC0gQk9TQSAoTlRSQkUtMDY3MTUxNjY0NykxDzANBgNVBAUTBjIwMjEwMjEXMBUGA1UEAwwOVGltZXN0YW1wIFVuaXQwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQgW045n8P+kf/32AZ+HfDC+it91DWvUg1VuyLBPXklBXS2aJ3SoWleLm9dbBIR+dN2VnGNpxJeWJwkrLV6ed6Co4IBqjCCAaYwDAYDVR0TAQH/BAIwADAfBgNVHSMEGDAWgBTgThvTdU21h04CtvqpWmPMPKqYmTB7BggrBgEFBQcBAQRvMG0wOgYIKwYBBQUHMAKGLmh0dHA6Ly9jcnQuZWlkcGtpLmJlbGdpdW0uYmUvdHMvdHNjYTIwMjEwMS5jcnQwLwYIKwYBBQUHMAGGI2h0dHA6Ly9vY3NwLmVpZHBraS5iZWxnaXVtLmJlL2VpZC8wMFYGA1UdIARPME0wQAYHYDgNBgOHaDA1MDMGCCsGAQUFBwIBFidodHRwczovL3JlcG9zaXRvcnkuZWlkcGtpLmJlbGdpdW0uYmUvdHMwCQYHBACL7EABATAWBgNVHSUBAf8EDDAKBggrBgEFBQcDCDAYBggrBgEFBQcBAwQMMAowCAYGBACORgEBMD8GA1UdHwQ4MDYwNKAyoDCGLmh0dHA6Ly9jcmwuZWlkcGtpLmJlbGdpdW0uYmUvdHMvdHNjYTIwMjEwMS5jcmwwHQYDVR0OBBYEFCz5Qqc7x2eYCEXyMH4p6AYCG5EQMA4GA1UdDwEB/wQEAwIHgDAKBggqhkjOPQQDAwNnADBkAjB0oreRkNZ7AxdtICH6lkW8nERAwDPWP8w5BUSZL8sJ5KrootY9gevtIn1+FbFTJRACMAi8hy0yn0pO0Pl4wzCmgcRhpaPmsmeJ8j3bo573kh1MK4psbY2Q3swkNu+8QWmi3g=="));
        trustedCertificateSource.addCertificate(DSSUtils.loadCertificateFromBase64EncodedString("MIIDaDCCAu2gAwIBAgIUcYtX/2tpPlocI17Yh6PvUfQBDyYwCgYIKoZIzj0EAwMwgeAxCzAJBgNVBAYTAkJFMREwDwYDVQQHDAhCcnVzc2VsczEwMC4GA1UECgwnS2luZ2RvbSBvZiBCZWxnaXVtIC0gRmVkZXJhbCBHb3Zlcm5tZW50MTYwNAYDVQQLDC1GUFMgSG9tZSBBZmZhaXJzIC0gQklLLUdDSSAoTlRSQkUtMDM2MjQ3NTUzOCkxOTA3BgNVBAsMMEZQUyBQb2xpY3kgYW5kIFN1cHBvcnQgLSBCT1NBIChOVFJCRS0wNjcxNTE2NjQ3KTEZMBcGA1UEAwwQQmVsZ2l1bSBSb290IENBNjAeFw0yMDA2MDMxMDAxMzFaFw00MDA2MDMxMDAxMzFaMIHgMQswCQYDVQQGEwJCRTERMA8GA1UEBwwIQnJ1c3NlbHMxMDAuBgNVBAoMJ0tpbmdkb20gb2YgQmVsZ2l1bSAtIEZlZGVyYWwgR292ZXJubWVudDE2MDQGA1UECwwtRlBTIEhvbWUgQWZmYWlycyAtIEJJSy1HQ0kgKE5UUkJFLTAzNjI0NzU1MzgpMTkwNwYDVQQLDDBGUFMgUG9saWN5IGFuZCBTdXBwb3J0IC0gQk9TQSAoTlRSQkUtMDY3MTUxNjY0NykxGTAXBgNVBAMMEEJlbGdpdW0gUm9vdCBDQTYwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAR532ARaLVsPSf5Pz9+b5ExaxpCe8iGGkDgkbUlGM0ulbr0YqbKva7EoOAY+YL5ZJs8S0KIsuQNc0f2vgI8xcyPQHgeCaLcw0OzvmfCHf/OMOIozEKgKaAK6pHvaBXP0tijZjBkMBIGA1UdEwEB/wQIMAYBAf8CAQEwHwYDVR0jBBgwFoAULqCIsAsNYonsHT/Un8ySRI5IaUYwHQYDVR0OBBYEFC6giLALDWKJ7B0/1J/MkkSOSGlGMA4GA1UdDwEB/wQEAwIBBjAKBggqhkjOPQQDAwNpADBmAjEAt2e2vVG4/aMjIokbQQuCnvI8so8rZl/IbKupMCJitfFi7oVlHllYFDdYMDTKWLZgAjEAsa2wuz3Ew6/68XXtIT+51snqkl2KLlaVgKXYlpTh2zqQBIBdKO1nMO/rQRfuZ701"));
        trustedCertificateSource.addCertificate(DSSUtils.loadCertificateFromBase64EncodedString("MIIGcjCCBFqgAwIBAgIUQT3qGijCJThFVY4Efz4qi1ubrq4wDQYJKoZIhvcNAQELBQAwRjELMAkGA1UEBhMCTFUxFjAUBgNVBAoMDUx1eFRydXN0IFMuQS4xHzAdBgNVBAMMFkx1eFRydXN0IEdsb2JhbCBSb290IDIwHhcNMTUwMzA2MTQxMjE1WhcNMzUwMzA1MTMyMTU3WjBOMQswCQYDVQQGEwJMVTEWMBQGA1UECgwNTHV4VHJ1c3QgUy5BLjEnMCUGA1UEAwweTHV4VHJ1c3QgR2xvYmFsIFF1YWxpZmllZCBDQSAzMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAuZ5iXSmFbP80gWb0kieYsImcyIo3QYg+XA3NlwH6QtI0PgZEG9dSo8pM7VMIzE5zq8tgJ50HnPdYflvfhkEKvAW2NuNX6hi/6HK4Nye+kB+INjpfAHmLft3GT95e+frk/t7hJNorK44xzqfWZKLNGysEHIriddcePWOk3J/VMc9CsSemeZbmeZW1/xXeqolMS7JIDZ3+0DgVCYsKIK+b3sAQ8iqXbQlQyvymG6QyoQoJbuEP23iawRMWKNWk+sjzOkPAAQDtgEEVdggzzudLSM04C5CjeLlLYuXgljler9bKRk9wW8nkareLZsn9uCDihGXGyC5m9jseGY1KAnlV8usLjBFAiW5OCnzcOg+CPsVucoRhS6uvXcu7VtHRGo5yLysJVv7sj6cx5lMvQKAMLviVi3kphZKYfqVLAVFJpXTpunY2GayVGf/uOpzNoiSRpcxxYjmAlPKNeTgXVl5Mc0zojgT/MZTGFN7ov7n01yodN6OhfTADacvaKfj2C2CwdCJvMqvlUuCKrvuXbdZrtRm3BZXrghGhuQmG0Tir7VVCI0WZjVjyHs2rpUcCQ6+D1WymKhzp0mrXdaFzYRce7FrEk69JWzWVp/9/GKnnb0//camavEaI4V64MVxYAir5AL/j7d4JIOqhPPU14ajxmC6dEH84guVs0Lo/dwVTUzsCAwEAAaOCAU4wggFKMBIGA1UdEwEB/wQIMAYBAf8CAQAwQwYDVR0gBDwwOjA4BggrgSsBAQEKAzAsMCoGCCsGAQUFBwIBFh5odHRwczovL3JlcG9zaXRvcnkubHV4dHJ1c3QubHUwagYIKwYBBQUHAQEEXjBcMCsGCCsGAQUFBzABhh9odHRwOi8vbHRncm9vdC5vY3NwLmx1eHRydXN0Lmx1MC0GCCsGAQUFBzAChiFodHRwOi8vY2EubHV4dHJ1c3QubHUvTFRHUkNBMi5jcnQwDgYDVR0PAQH/BAQDAgEGMB8GA1UdIwQYMBaAFP8YKHb5SAUsoa7xKxsrslP4S3yzMDMGA1UdHwQsMCowKKAmoCSGImh0dHA6Ly9jcmwubHV4dHJ1c3QubHUvTFRHUkNBMi5jcmwwHQYDVR0OBBYEFGOPwosDsauO2FNHlh2ZqH32rKh1MA0GCSqGSIb3DQEBCwUAA4ICAQADB6M/edbOO9iJCOnVxayJ1NBk08/BVKlHwe7HBYAzT6Kmo3TbMUwOpcGI2e/NBCR3F4wTzXOVvFmvdBl7sdS6uMSLBTrav+5LChcFDBQj26X5VQDcXkA8b/u6J4Ve7CwoSesYg9H0fsJ3v12QrmGUUao9gbamKP1TFriO+XiIaDLYectruusRktIke9qy8MCpNSarZqr3oD3c/+N5D3lDlGpaz1IL8TpbubFEQHPCr6JiwR+qSqGRfxv8vIvOOAVxe7np5QhtwmCkXdMOPQ/XOOuEA06bez+zHkASX64at7dXru+4JUEbpijjMA+1jbFZr20OeBIQZL7oEst+FF8lFuvmucC9TS9QnlF28WJExvpIknjS7LhFMGXB9w380q38ZOuKjPZpoztYeyUpf8gxzV7fE5Q1okhnsDZ+12vBzBruzJcwtNuXyLyIh3fVN0LunVd+NP2kGjB2t9WD2Y0CaKxWx8snDdrSbAi46TpNoe04eroWgZOvdN0hEmf2d8tYBSJ/XZekU9sCAww5vxHnXJi6CZHhjt8f1mMhyE2gBvmpk4CFetViO2sG0n/nsxCQNpnclsax/eJuXmGiZ3OPCIRijI5gy3pLRgnbgLyktWoOkmT/gxtWDLfVZwEt52JL8d550KIgttyRqX81LJWGSDdpnzeRVQEnzAt6+RebAQ=="));
        certificateVerifier.setTrustedCertSources(trustedCertificateSource);
        return certificateVerifier;
    }

    @Override
    protected void checkEvidenceRecordType(EvidenceRecordWrapper evidenceRecord) {
        super.checkEvidenceRecordType(evidenceRecord);

        assertEquals(EvidenceRecordTypeEnum.XML_EVIDENCE_RECORD, evidenceRecord.getEvidenceRecordType());
    }

    @Override
    protected void checkEvidenceRecordDigestMatchers(DiagnosticData diagnosticData) {
        EvidenceRecordWrapper evidenceRecordWrapper = diagnosticData.getEvidenceRecords().get(0);
        assertEquals(2, evidenceRecordWrapper.getDigestMatchers().size());

        int docRefCounter = 0;
        int sigRefCounter = 0;
        for (XmlDigestMatcher digestMatcher : evidenceRecordWrapper.getDigestMatchers()) {
            if (DigestMatcherType.EVIDENCE_RECORD_ARCHIVE_OBJECT == digestMatcher.getType()) {
                assertNotNull(digestMatcher.getDocumentName());
                assertTrue(digestMatcher.isDataFound());
                assertTrue(digestMatcher.isDataIntact());
                assertNotNull(digestMatcher.getDigestMethod());
                assertNotNull(digestMatcher.getDigestValue());
                ++docRefCounter;
            } else if (DigestMatcherType.EVIDENCE_RECORD_MASTER_SIGNATURE == digestMatcher.getType()) {
                assertNull(digestMatcher.getDocumentName());
                assertFalse(digestMatcher.isDataFound());
                assertFalse(digestMatcher.isDataIntact());
                assertNull(digestMatcher.getDigestMethod());
                assertNull(digestMatcher.getDigestValue());
                ++sigRefCounter;
            }
        }
        assertEquals(1, docRefCounter);
        assertEquals(1, sigRefCounter);
    }

    @Override
    protected void checkEvidenceRecordScopes(DiagnosticData diagnosticData) {
        EvidenceRecordWrapper evidenceRecordWrapper = diagnosticData.getEvidenceRecords().get(0);
        assertEquals(1, Utils.collectionSize(evidenceRecordWrapper.getEvidenceRecordScopes()));

        XmlSignatureScope xmlSignatureScope = evidenceRecordWrapper.getEvidenceRecordScopes().get(0);
        assertEquals(SignatureScopeType.FULL, xmlSignatureScope.getScope());
        assertEquals("sample.xml", xmlSignatureScope.getName());
        assertNotNull(xmlSignatureScope.getDescription());
    }

    @Override
    protected void checkEvidenceRecordCoverage(DiagnosticData diagnosticData, SignatureWrapper signature) {
        EvidenceRecordWrapper evidenceRecord = diagnosticData.getEvidenceRecords().get(0);

        int coversSignatureCounter = 0;
        int coversSignedDataCounter = 0;
        int coversCertificatesCounter = 0;
        int coversRevocationDataCounter = 0;
        int coversTimestampsCounter = 0;
        int coversEvidenceRecordsCounter = 0;

        List<XmlTimestampedObject> coveredObjects = evidenceRecord.getCoveredObjects();
        assertTrue(Utils.isCollectionNotEmpty(coveredObjects));
        for (XmlTimestampedObject reference : coveredObjects) {
            if (TimestampedObjectType.SIGNATURE == reference.getCategory()) {
                ++coversSignatureCounter;
            } else if (TimestampedObjectType.SIGNED_DATA == reference.getCategory()) {
                ++coversSignedDataCounter;
            } else if (TimestampedObjectType.CERTIFICATE == reference.getCategory()) {
                ++coversCertificatesCounter;
            } else if (TimestampedObjectType.REVOCATION == reference.getCategory()) {
                ++coversRevocationDataCounter;
            } else if (TimestampedObjectType.TIMESTAMP == reference.getCategory()) {
                ++coversTimestampsCounter;
            } else if (TimestampedObjectType.EVIDENCE_RECORD == reference.getCategory()) {
                ++coversEvidenceRecordsCounter;
            }
        }
        assertEquals(1, coversSignatureCounter);
        assertEquals(1, coversSignedDataCounter);
        assertEquals(8, coversCertificatesCounter);
        assertEquals(2, coversRevocationDataCounter);
        assertEquals(1, coversTimestampsCounter);
        assertEquals(0, coversEvidenceRecordsCounter);

        TimestampWrapper timestamp = evidenceRecord.getTimestampList().get(0);

        coversSignatureCounter = 0;
        coversSignedDataCounter = 0;
        coversCertificatesCounter = 0;
        coversRevocationDataCounter = 0;
        coversTimestampsCounter = 0;
        coversEvidenceRecordsCounter = 0;

        coveredObjects = timestamp.getTimestampedObjects();
        assertTrue(Utils.isCollectionNotEmpty(coveredObjects));
        for (XmlTimestampedObject reference : coveredObjects) {
            if (TimestampedObjectType.SIGNATURE == reference.getCategory()) {
                ++coversSignatureCounter;
            } else if (TimestampedObjectType.SIGNED_DATA == reference.getCategory()) {
                ++coversSignedDataCounter;
            } else if (TimestampedObjectType.CERTIFICATE == reference.getCategory()) {
                ++coversCertificatesCounter;
            } else if (TimestampedObjectType.REVOCATION == reference.getCategory()) {
                ++coversRevocationDataCounter;
            } else if (TimestampedObjectType.TIMESTAMP == reference.getCategory()) {
                ++coversTimestampsCounter;
            } else if (TimestampedObjectType.EVIDENCE_RECORD == reference.getCategory()) {
                ++coversEvidenceRecordsCounter;
            }
        }
        assertEquals(1, coversSignatureCounter);
        assertEquals(1, coversSignedDataCounter);
        assertEquals(8, coversCertificatesCounter);
        assertEquals(2, coversRevocationDataCounter);
        assertEquals(1, coversTimestampsCounter);
        assertEquals(1, coversEvidenceRecordsCounter);
    }

    @Override
    protected int getNumberOfExpectedEvidenceScopes() {
        return 1;
    }

    @Override
    protected void verifySimpleReport(SimpleReport simpleReport) {
        int sigWithErCounter = 0;
        for (String sigId : simpleReport.getSignatureIdList()) {
            List<XmlEvidenceRecord> signatureEvidenceRecords = simpleReport.getSignatureEvidenceRecords(sigId);
            if (Utils.isCollectionNotEmpty(signatureEvidenceRecords)) {
                ++sigWithErCounter;
            }

            XmlEvidenceRecord evidenceRecord = signatureEvidenceRecords.get(0);
            assertEquals(Indication.INDETERMINATE, evidenceRecord.getIndication());
            assertEquals(SubIndication.SIGNED_DATA_NOT_FOUND, evidenceRecord.getSubIndication());

            assertEquals(1, Utils.collectionSize(evidenceRecord.getEvidenceRecordScope()));
        }
        assertEquals(1, sigWithErCounter);
    }

    @Override
    protected void verifyETSIValidationReport(ValidationReportType etsiValidationReportJaxb) {
        List<SignatureValidationReportType> signatureValidationReports = etsiValidationReportJaxb.getSignatureValidationReport();
        assertTrue(Utils.isCollectionNotEmpty(signatureValidationReports));

        SignatureValidationReportType signatureValidationReportType = signatureValidationReports.get(0);
        assertNotEquals(Indication.NO_SIGNATURE_FOUND, signatureValidationReportType.getSignatureValidationStatus().getMainIndication());

        ValidationObjectListType signatureValidationObjects = etsiValidationReportJaxb.getSignatureValidationObjects();
        assertNotNull(signatureValidationObjects);

        List<ValidationObjectType> validationObjects = signatureValidationObjects.getValidationObject();
        assertTrue(Utils.isCollectionNotEmpty(validationObjects));

        boolean evidenceRecordFound = false;
        boolean tstFound = false;
        for (ValidationObjectType validationObjectType : validationObjects) {
            if (ObjectType.EVIDENCE_RECORD == validationObjectType.getObjectType()) {
                assertNotNull(validationObjectType.getObjectType());
                POEType poeType = validationObjectType.getPOE();
                assertNotNull(poeType);
                assertNull(poeType.getPOEObject());
                assertEquals(TypeOfProof.VALIDATION, poeType.getTypeOfProof());
                assertNotNull(poeType.getPOETime());

                POEProvisioningType poeProvisioning = validationObjectType.getPOEProvisioning();
                assertNotNull(poeProvisioning);
                assertNotNull(poeProvisioning.getPOETime());
                assertTrue(Utils.isCollectionNotEmpty(poeProvisioning.getValidationObject()));

                SignatureValidationReportType validationReport = validationObjectType.getValidationReport();
                assertNotNull(validationReport);

                ValidationStatusType signatureValidationStatus = validationReport.getSignatureValidationStatus();
                assertNotNull(signatureValidationStatus);
                assertNotNull(signatureValidationStatus.getMainIndication());
                if (Indication.PASSED != signatureValidationStatus.getMainIndication()) {
                    assertTrue(Utils.isCollectionNotEmpty(signatureValidationStatus.getSubIndication()));
                    assertNotNull(signatureValidationStatus.getSubIndication().get(0));
                }

                List<ValidationReportDataType> associatedValidationReportData = signatureValidationStatus.getAssociatedValidationReportData();
                assertEquals(1, associatedValidationReportData.size());

                ValidationReportDataType validationReportDataType = associatedValidationReportData.get(0);
                CryptoInformationType cryptoInformation = validationReportDataType.getCryptoInformation();
                assertNotNull(cryptoInformation);
                assertEquals(1, cryptoInformation.getValidationObjectId().getVOReference().size());
                assertEquals("urn:etsi:019102:algorithm:unidentified", cryptoInformation.getAlgorithm());
                assertFalse(cryptoInformation.isSecureAlgorithm());

                ValidationObjectRepresentationType validationObjectRepresentation = validationObjectType.getValidationObjectRepresentation();
                assertNotNull(validationObjectRepresentation);

                List<Object> directOrBase64OrDigestAlgAndValue = validationObjectRepresentation.getDirectOrBase64OrDigestAlgAndValue();
                assertEquals(1, directOrBase64OrDigestAlgAndValue.size());

                if (getTokenExtractionStrategy().isEvidenceRecord()) {
                    assertInstanceOf(byte[].class, directOrBase64OrDigestAlgAndValue.get(0));
                    assertNotNull(directOrBase64OrDigestAlgAndValue.get(0));
                } else {
                    assertInstanceOf(DigestAlgAndValueType.class, directOrBase64OrDigestAlgAndValue.get(0));
                    DigestAlgAndValueType digestAlgAndValueType = (DigestAlgAndValueType) directOrBase64OrDigestAlgAndValue.get(0);
                    assertNotNull(DigestAlgorithm.forXML(digestAlgAndValueType.getDigestMethod().getAlgorithm()));
                    assertNotNull(digestAlgAndValueType.getDigestValue());
                }

                evidenceRecordFound = true;

            } else if (ObjectType.TIMESTAMP == validationObjectType.getObjectType()) {
                tstFound = true;
            }
        }
        assertTrue(evidenceRecordFound);
        assertTrue(tstFound);
    }

}
