package eu.europa.esig.dss.xades.signature;

import eu.europa.esig.dss.detailedreport.DetailedReport;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.RelatedCertificateWrapper;
import eu.europa.esig.dss.diagnostic.RelatedRevocationWrapper;
import eu.europa.esig.dss.diagnostic.RevocationWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.ArchiveTimestampType;
import eu.europa.esig.dss.enumerations.CertificateOrigin;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.RevocationOrigin;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.enumerations.ValidationDataContainerType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.test.PKIFactoryAccess;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

@Tag("slow")
class XAdESDoubleLTAWithValDataContainerTypesTest extends PKIFactoryAccess {

    private static Stream<Arguments> data() {
        List<Arguments> args = new ArrayList<>();
        for (int i = 0; i < ValidationDataContainerType.values().length; i++) {
            for (int h = 0; h < ValidationDataContainerType.values().length; h++) {
                args.add(Arguments.of(ValidationDataContainerType.values()[i], ValidationDataContainerType.values()[h]));
            }
        }
        return args.stream();
    }

    @ParameterizedTest(name = "XAdES DoubleLTA {index} : {0} - {1}")
    @MethodSource("data")
    void test(ValidationDataContainerType validationDataTypeOnSigning, ValidationDataContainerType validationDataTypeOnExtension) throws IOException {
        DSSDocument documentToSign = new FileDocument("src/test/resources/sample.xml");

        XAdESSignatureParameters signatureParameters = new XAdESSignatureParameters();
        signatureParameters.bLevel().setSigningDate(new Date());
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_LT);
        signatureParameters.setSignaturePackaging(SignaturePackaging.DETACHED);

        signatureParameters.setValidationDataContainerType(validationDataTypeOnSigning);

        XAdESService service = new XAdESService(getCompleteCertificateVerifier());

        Calendar tspTime = Calendar.getInstance();
        tspTime.add(Calendar.MINUTE, 1);
        service.setTspSource(getGoodTsaByTime(tspTime.getTime()));

        ToBeSigned dataToSign = service.getDataToSign(documentToSign, signatureParameters);
        SignatureValue signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
        DSSDocument signedDocument = service.signDocument(documentToSign, signatureParameters, signatureValue);

        SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signedDocument);
        validator.setCertificateVerifier(getOfflineCertificateVerifier());
        validator.setDetachedContents(Collections.singletonList(documentToSign));
        Reports reports = validator.validateDocument();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));

        DetailedReport detailedReport = reports.getDetailedReport();
        List<String> timestampIds = detailedReport.getTimestampIds();
        assertEquals(1, timestampIds.size());

        DiagnosticData diagnosticData = reports.getDiagnosticData();
        assertContainsAllRevocationData(diagnosticData);
        checkValidationDataOriginsOnSignature(diagnosticData, validationDataTypeOnSigning);

        // signedDocument.save("target/signed.xml");

        service.setTspSource(getGoodTsaCrossCertification());

        XAdESSignatureParameters extendParameters = new XAdESSignatureParameters();
        extendParameters.setDetachedContents(Collections.singletonList(documentToSign));
        extendParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_LTA);
        extendParameters.setValidationDataContainerType(validationDataTypeOnExtension);

        DSSDocument extendedDocument = service.extendDocument(signedDocument, extendParameters);

        awaitOneSecond();

        DSSDocument doubleLTADoc = service.extendDocument(extendedDocument, extendParameters);

        doubleLTADoc.save("target/doubleLTA.xml");

        validator = SignedDocumentValidator.fromDocument(doubleLTADoc);
        validator.setCertificateVerifier(getOfflineCertificateVerifier());
        validator.setDetachedContents(Collections.singletonList(documentToSign));
        reports = validator.validateDocument();

        reports.print();

        simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));

        detailedReport = reports.getDetailedReport();
        timestampIds = detailedReport.getTimestampIds();
        assertEquals(3, timestampIds.size());

        diagnosticData = reports.getDiagnosticData();
        assertContainsAllRevocationData(diagnosticData);
        checkValidationDataOriginsOnExtension(diagnosticData, validationDataTypeOnExtension);

        int archiveTimestampCounter = 0;
        for (String id : timestampIds) {
            assertEquals(Indication.PASSED, detailedReport.getBasicTimestampValidationIndication(id));
            TimestampWrapper timestamp = diagnosticData.getTimestampById(id);
            if (TimestampType.ARCHIVE_TIMESTAMP.equals(timestamp.getType())) {
                assertEquals(ArchiveTimestampType.XAdES_141, timestamp.getArchiveTimestampType());
                archiveTimestampCounter++;
            }
        }
        assertEquals(2, archiveTimestampCounter);
    }

    @Override
    protected CertificateVerifier getCompleteCertificateVerifier() {
        // no cache
        CertificateVerifier certificateVerifier = super.getCompleteCertificateVerifier();
        certificateVerifier.setCrlSource(pkiCRLSource());
        certificateVerifier.setOcspSource(pkiDelegatedOCSPSource());
        return certificateVerifier;
    }

    private void assertContainsAllRevocationData(DiagnosticData diagnosticData) {
        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        assertContainsAllRevocationData(signature.getCertificateChain());
        for (TimestampWrapper timestamp : diagnosticData.getTimestampList()) {
            assertContainsAllRevocationData(timestamp.getCertificateChain());
        }
        for (RevocationWrapper revocation : diagnosticData.getAllRevocationData()) {
            assertContainsAllRevocationData(revocation.getCertificateChain());
        }
    }

    private void assertContainsAllRevocationData(List<CertificateWrapper> certificateChain) {
        for (CertificateWrapper certificate : certificateChain) {
            if (certificate.isTrusted()) {
                break;
            }
            assertTrue(certificate.isRevocationDataAvailable() || certificate.isSelfSigned(),
                    "Certificate with id : [" + certificate.getId() + "] does not have a revocation data!");
        }
    }

    private void checkValidationDataOriginsOnSignature(DiagnosticData diagnosticData, ValidationDataContainerType validationDataContainerType) {
        switch (validationDataContainerType) {
            case CERTIFICATE_REVOCATION_VALUES_AND_TIMESTAMP_VALIDATION_DATA:
                assertContainsCertificatesOfOrigin(diagnosticData, CertificateOrigin.KEY_INFO, CertificateOrigin.CERTIFICATE_VALUES);
                assertContainsRevocationOfOrigin(diagnosticData, RevocationOrigin.REVOCATION_VALUES);
                break;
            case CERTIFICATE_REVOCATION_VALUES_AND_TIMESTAMP_VALIDATION_DATA_AND_ANY_VALIDATION_DATA:
                assertContainsCertificatesOfOrigin(diagnosticData, CertificateOrigin.KEY_INFO, CertificateOrigin.CERTIFICATE_VALUES, CertificateOrigin.TIMESTAMP_VALIDATION_DATA);
                assertContainsRevocationOfOrigin(diagnosticData, RevocationOrigin.REVOCATION_VALUES, RevocationOrigin.TIMESTAMP_VALIDATION_DATA);
                break;
            case CERTIFICATE_REVOCATION_VALUES_AND_ANY_VALIDATION_DATA:
                assertContainsCertificatesOfOrigin(diagnosticData, CertificateOrigin.KEY_INFO, CertificateOrigin.CERTIFICATE_VALUES, CertificateOrigin.ANY_VALIDATION_DATA);
                assertContainsRevocationOfOrigin(diagnosticData, RevocationOrigin.REVOCATION_VALUES, RevocationOrigin.ANY_VALIDATION_DATA);
                break;
            case ANY_VALIDATION_DATA_ONLY:
                assertContainsCertificatesOfOrigin(diagnosticData, CertificateOrigin.KEY_INFO, CertificateOrigin.ANY_VALIDATION_DATA);
                assertContainsRevocationOfOrigin(diagnosticData, RevocationOrigin.ANY_VALIDATION_DATA);
                break;
            default:
                fail(String.format("Not supported type %s", validationDataContainerType));
        }
    }

    private void checkValidationDataOriginsOnExtension(DiagnosticData diagnosticData, ValidationDataContainerType validationDataContainerType) {
        switch (validationDataContainerType) {
            case CERTIFICATE_REVOCATION_VALUES_AND_TIMESTAMP_VALIDATION_DATA:
                assertContainsCertificatesOfOrigin(diagnosticData, CertificateOrigin.KEY_INFO, CertificateOrigin.CERTIFICATE_VALUES, CertificateOrigin.TIMESTAMP_VALIDATION_DATA);
                assertContainsRevocationOfOrigin(diagnosticData, RevocationOrigin.REVOCATION_VALUES, RevocationOrigin.TIMESTAMP_VALIDATION_DATA);
                break;
            case CERTIFICATE_REVOCATION_VALUES_AND_TIMESTAMP_VALIDATION_DATA_AND_ANY_VALIDATION_DATA:
                assertContainsCertificatesOfOrigin(diagnosticData, CertificateOrigin.KEY_INFO, CertificateOrigin.CERTIFICATE_VALUES, CertificateOrigin.TIMESTAMP_VALIDATION_DATA);
                assertContainsRevocationOfOrigin(diagnosticData, RevocationOrigin.REVOCATION_VALUES, RevocationOrigin.TIMESTAMP_VALIDATION_DATA, RevocationOrigin.ANY_VALIDATION_DATA);
                break;
            case CERTIFICATE_REVOCATION_VALUES_AND_ANY_VALIDATION_DATA:
                assertContainsCertificatesOfOrigin(diagnosticData, CertificateOrigin.KEY_INFO, CertificateOrigin.CERTIFICATE_VALUES, CertificateOrigin.ANY_VALIDATION_DATA);
                assertContainsRevocationOfOrigin(diagnosticData, RevocationOrigin.REVOCATION_VALUES, RevocationOrigin.ANY_VALIDATION_DATA);
                break;
            case ANY_VALIDATION_DATA_ONLY:
                assertContainsCertificatesOfOrigin(diagnosticData, CertificateOrigin.KEY_INFO, CertificateOrigin.ANY_VALIDATION_DATA);
                assertContainsRevocationOfOrigin(diagnosticData, RevocationOrigin.ANY_VALIDATION_DATA);
                break;
            default:
                fail(String.format("Not supported type %s", validationDataContainerType));
        }
    }

    private void assertContainsCertificatesOfOrigin(DiagnosticData diagnosticData, CertificateOrigin... origins) {
        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        Set<CertificateOrigin> foundOrigins = new HashSet<>();
        for (RelatedCertificateWrapper certificateWrapper : signature.foundCertificates().getRelatedCertificates()) {
            for (CertificateOrigin origin : certificateWrapper.getOrigins()) {
                if (Arrays.stream(origins).noneMatch(o -> o == origin)) {
                    fail(String.format("No '%s' origin is allowed by test configuration!", origin));
                }
                foundOrigins.add(origin);
            }
        }
        assertEquals(new HashSet<>(Arrays.asList(origins)), foundOrigins);
        assertTrue(Utils.isCollectionEmpty(signature.foundCertificates().getOrphanCertificates()));
    }

    private void assertContainsRevocationOfOrigin(DiagnosticData diagnosticData, RevocationOrigin... origins) {
        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        Set<RevocationOrigin> foundOrigins = new HashSet<>();
        for (RelatedRevocationWrapper revocationWrapper : signature.foundRevocations().getRelatedRevocationData()) {
            for (RevocationOrigin origin : revocationWrapper.getOrigins()) {
                if (Arrays.stream(origins).noneMatch(o -> o == origin)) {
                    fail(String.format("No '%s' origin is allowed by test configuration!", origin));
                }
                foundOrigins.add(origin);
            }
        }
        assertEquals(new HashSet<>(Arrays.asList(origins)), foundOrigins);
        assertTrue(Utils.isCollectionEmpty(signature.foundRevocations().getOrphanRevocationData()));
    }

    @Override
    protected String getSigningAlias() {
        return RSA_SHA3_USER;
    }

}
