package eu.europa.esig.dss.xades.preservation;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.EvidenceRecordWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTimestampedObject;
import eu.europa.esig.dss.enumerations.EvidenceRecordTypeEnum;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.TimestampedObjectType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.exception.IllegalInputException;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.utils.Utils;
import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class XAdESLevelLTDetachedAddXMLEvidenceRecordByIdTest extends AbstractXAdESAddEvidenceRecordTest {

    private List<DSSDocument> detachedContents = null;

    @Override
    protected DSSDocument getSignatureDocument() {
        return new FileDocument("src/test/resources/validation/evidence-record/incorporation/X-B-LT-detached.xml");
    }

    @Override
    protected DSSDocument getEvidenceRecordDocument() {
        return new FileDocument("src/test/resources/validation/evidence-record/incorporation/evidence-record-X-B-LT-detached.xml");
    }

    @Override
    protected void checkSignatureLevel(DiagnosticData diagnosticData) {
        assertEquals(SignatureLevel.XAdES_ERS, diagnosticData.getSignatureFormat(diagnosticData.getFirstSignatureId()));
    }

    @Override
    protected EvidenceRecordTypeEnum getEvidenceRecordType() {
        return EvidenceRecordTypeEnum.XML_EVIDENCE_RECORD;
    }

    @Override
    protected CertificateVerifier getOfflineCertificateVerifier() {
        CertificateVerifier certificateVerifier = super.getOfflineCertificateVerifier();
        CommonTrustedCertificateSource trustedCertificateSource = new CommonTrustedCertificateSource();
        trustedCertificateSource.addCertificate(DSSUtils.loadCertificateFromBase64EncodedString("MIIERzCCA86gAwIBAgIUEFsEYuhn+NxO8EbEovbXNQS+YskwCgYIKoZIzj0EAwMwgbsxCzAJBgNVBAYTAkJFMREwDwYDVQQHDAhCcnVzc2VsczEwMC4GA1UECgwnS2luZ2RvbSBvZiBCZWxnaXVtIC0gRmVkZXJhbCBHb3Zlcm5tZW50MT8wPQYDVQQLDDZRVFNQOiBGUFMgUG9saWN5IGFuZCBTdXBwb3J0IC0gQk9TQSAoTlRSQkUtMDY3MTUxNjY0NykxDzANBgNVBAUTBjIwMjEwMTEVMBMGA1UEAwwMVGltZXN0YW1wIENBMB4XDTIxMDMxNjA5NDAyNFoXDTI3MDMxNjA5NDAyNFowgb0xCzAJBgNVBAYTAkJFMREwDwYDVQQHDAhCcnVzc2VsczEwMC4GA1UECgwnS2luZ2RvbSBvZiBCZWxnaXVtIC0gRmVkZXJhbCBHb3Zlcm5tZW50MT8wPQYDVQQLDDZRVFNQOiBGUFMgUG9saWN5IGFuZCBTdXBwb3J0IC0gQk9TQSAoTlRSQkUtMDY3MTUxNjY0NykxDzANBgNVBAUTBjIwMjEwMjEXMBUGA1UEAwwOVGltZXN0YW1wIFVuaXQwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQgW045n8P+kf/32AZ+HfDC+it91DWvUg1VuyLBPXklBXS2aJ3SoWleLm9dbBIR+dN2VnGNpxJeWJwkrLV6ed6Co4IBqjCCAaYwDAYDVR0TAQH/BAIwADAfBgNVHSMEGDAWgBTgThvTdU21h04CtvqpWmPMPKqYmTB7BggrBgEFBQcBAQRvMG0wOgYIKwYBBQUHMAKGLmh0dHA6Ly9jcnQuZWlkcGtpLmJlbGdpdW0uYmUvdHMvdHNjYTIwMjEwMS5jcnQwLwYIKwYBBQUHMAGGI2h0dHA6Ly9vY3NwLmVpZHBraS5iZWxnaXVtLmJlL2VpZC8wMFYGA1UdIARPME0wQAYHYDgNBgOHaDA1MDMGCCsGAQUFBwIBFidodHRwczovL3JlcG9zaXRvcnkuZWlkcGtpLmJlbGdpdW0uYmUvdHMwCQYHBACL7EABATAWBgNVHSUBAf8EDDAKBggrBgEFBQcDCDAYBggrBgEFBQcBAwQMMAowCAYGBACORgEBMD8GA1UdHwQ4MDYwNKAyoDCGLmh0dHA6Ly9jcmwuZWlkcGtpLmJlbGdpdW0uYmUvdHMvdHNjYTIwMjEwMS5jcmwwHQYDVR0OBBYEFCz5Qqc7x2eYCEXyMH4p6AYCG5EQMA4GA1UdDwEB/wQEAwIHgDAKBggqhkjOPQQDAwNnADBkAjB0oreRkNZ7AxdtICH6lkW8nERAwDPWP8w5BUSZL8sJ5KrootY9gevtIn1+FbFTJRACMAi8hy0yn0pO0Pl4wzCmgcRhpaPmsmeJ8j3bo573kh1MK4psbY2Q3swkNu+8QWmi3g=="));
        trustedCertificateSource.addCertificate(DSSUtils.loadCertificateFromBase64EncodedString("MIIDaDCCAu2gAwIBAgIUcYtX/2tpPlocI17Yh6PvUfQBDyYwCgYIKoZIzj0EAwMwgeAxCzAJBgNVBAYTAkJFMREwDwYDVQQHDAhCcnVzc2VsczEwMC4GA1UECgwnS2luZ2RvbSBvZiBCZWxnaXVtIC0gRmVkZXJhbCBHb3Zlcm5tZW50MTYwNAYDVQQLDC1GUFMgSG9tZSBBZmZhaXJzIC0gQklLLUdDSSAoTlRSQkUtMDM2MjQ3NTUzOCkxOTA3BgNVBAsMMEZQUyBQb2xpY3kgYW5kIFN1cHBvcnQgLSBCT1NBIChOVFJCRS0wNjcxNTE2NjQ3KTEZMBcGA1UEAwwQQmVsZ2l1bSBSb290IENBNjAeFw0yMDA2MDMxMDAxMzFaFw00MDA2MDMxMDAxMzFaMIHgMQswCQYDVQQGEwJCRTERMA8GA1UEBwwIQnJ1c3NlbHMxMDAuBgNVBAoMJ0tpbmdkb20gb2YgQmVsZ2l1bSAtIEZlZGVyYWwgR292ZXJubWVudDE2MDQGA1UECwwtRlBTIEhvbWUgQWZmYWlycyAtIEJJSy1HQ0kgKE5UUkJFLTAzNjI0NzU1MzgpMTkwNwYDVQQLDDBGUFMgUG9saWN5IGFuZCBTdXBwb3J0IC0gQk9TQSAoTlRSQkUtMDY3MTUxNjY0NykxGTAXBgNVBAMMEEJlbGdpdW0gUm9vdCBDQTYwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAR532ARaLVsPSf5Pz9+b5ExaxpCe8iGGkDgkbUlGM0ulbr0YqbKva7EoOAY+YL5ZJs8S0KIsuQNc0f2vgI8xcyPQHgeCaLcw0OzvmfCHf/OMOIozEKgKaAK6pHvaBXP0tijZjBkMBIGA1UdEwEB/wQIMAYBAf8CAQEwHwYDVR0jBBgwFoAULqCIsAsNYonsHT/Un8ySRI5IaUYwHQYDVR0OBBYEFC6giLALDWKJ7B0/1J/MkkSOSGlGMA4GA1UdDwEB/wQEAwIBBjAKBggqhkjOPQQDAwNpADBmAjEAt2e2vVG4/aMjIokbQQuCnvI8so8rZl/IbKupMCJitfFi7oVlHllYFDdYMDTKWLZgAjEAsa2wuz3Ew6/68XXtIT+51snqkl2KLlaVgKXYlpTh2zqQBIBdKO1nMO/rQRfuZ701"));
        trustedCertificateSource.addCertificate(DSSUtils.loadCertificateFromBase64EncodedString("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"));
        certificateVerifier.setTrustedCertSources(trustedCertificateSource);
        return certificateVerifier;
    }

    @Test
    @Override
    public void addERAndValidate() {
        Exception exception = assertThrows(IllegalInputException.class, super::addERAndValidate);
        assertEquals("The digest covered by the evidence record do not correspond to " +
                "the digest computed on the signature and/or detached content! " +
                "In case of detached signature, please use #setDetachedContent method to provide original documents.",
                exception.getMessage());

        detachedContents = Collections.singletonList(new FileDocument("src/test/resources/sample.txt"));
        exception = assertThrows(IllegalInputException.class, super::addERAndValidate);
        assertEquals("The digest covered by the evidence record do not correspond to " +
                        "the digest computed on the signature and/or detached content!",
                exception.getMessage());

        detachedContents = Collections.singletonList(new FileDocument("src/test/resources/sample.xml"));
        super.addERAndValidate();
    }

    @Override
    protected void checkEvidenceRecordCoverage(DiagnosticData diagnosticData, SignatureWrapper signature) {
        List<SignatureWrapper> signatures = diagnosticData.getSignatures();

        List<EvidenceRecordWrapper> evidenceRecords = diagnosticData.getEvidenceRecords();
        EvidenceRecordWrapper evidenceRecord = evidenceRecords.get(0);
        List<XmlTimestampedObject> coveredObjects = evidenceRecord.getCoveredObjects();
        assertTrue(Utils.isCollectionNotEmpty(coveredObjects));

        assertEquals(Utils.collectionSize(signatures), coveredObjects.stream()
                .filter(r -> TimestampedObjectType.SIGNATURE == r.getCategory()).count());
        assertTrue(Utils.isCollectionNotEmpty(coveredObjects.stream()
                .filter(r -> TimestampedObjectType.SIGNED_DATA == r.getCategory()).collect(Collectors.toList())));

        assertTrue(Utils.isCollectionNotEmpty(evidenceRecord.getCoveredCertificates()));
        assertTrue(Utils.isCollectionNotEmpty(evidenceRecord.getCoveredRevocations()));
        assertTrue(Utils.isCollectionNotEmpty(evidenceRecord.getCoveredTimestamps()));
        assertTrue(Utils.isCollectionNotEmpty(evidenceRecord.getCoveredSignedData()));
    }

    @Override
    public List<DSSDocument> getDetachedContents() {
        return detachedContents;
    }

}
