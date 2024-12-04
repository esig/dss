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
import eu.europa.esig.dss.enumerations.ValidationDataEncapsulationStrategy;
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
import eu.europa.esig.dss.xades.DSSXMLUtils;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.definition.xades132.XAdES132Path;
import eu.europa.esig.dss.xml.utils.DomUtils;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

@Tag("slow")
class XAdESDoubleLTAWithValDataContainerTypesTest extends PKIFactoryAccess {

    private static Stream<Arguments> data() {
        List<Arguments> args = new ArrayList<>();
        for (int i = 0; i < ValidationDataEncapsulationStrategy.values().length; i++) {
            for (int h = 0; h < ValidationDataEncapsulationStrategy.values().length; h++) {
                args.add(Arguments.of(ValidationDataEncapsulationStrategy.values()[i], ValidationDataEncapsulationStrategy.values()[h]));
            }
        }
        return args.stream();
    }

    @ParameterizedTest(name = "XAdES DoubleLTA {index} : {0} - {1}")
    @MethodSource("data")
    void test(ValidationDataEncapsulationStrategy validationDataTypeOnSigning, ValidationDataEncapsulationStrategy validationDataTypeOnExtension) throws IOException {
        DSSDocument documentToSign = new FileDocument("src/test/resources/sample.xml");

        XAdESSignatureParameters signatureParameters = new XAdESSignatureParameters();
        signatureParameters.bLevel().setSigningDate(new Date());
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_LT);
        signatureParameters.setSignaturePackaging(SignaturePackaging.DETACHED);

        signatureParameters.setValidationDataEncapsulationStrategy(validationDataTypeOnSigning);

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

        checkOnSigned(signedDocument, 0, validationDataTypeOnSigning);

        XAdESSignatureParameters extendParameters = new XAdESSignatureParameters();
        extendParameters.setDetachedContents(Collections.singletonList(documentToSign));
        extendParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_LT);
        extendParameters.setValidationDataEncapsulationStrategy(validationDataTypeOnExtension);

        DSSDocument ltUpdatedDocument = service.extendDocument(signedDocument, extendParameters);
        checkOnSigned(ltUpdatedDocument, 0, validationDataTypeOnExtension);

        tspTime = Calendar.getInstance();
        tspTime.add(Calendar.MINUTE, 1);
        service.setTspSource(getKeyStoreTSPSourceByNameAndTime(GOOD_TSA_CROSS_CERTIF, tspTime.getTime()));

        extendParameters = new XAdESSignatureParameters();
        extendParameters.setDetachedContents(Collections.singletonList(documentToSign));
        extendParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_LTA);
        extendParameters.setValidationDataEncapsulationStrategy(validationDataTypeOnExtension);

        DSSDocument extendedDocument = service.extendDocument(signedDocument, extendParameters);

        checkOnSigned(extendedDocument, 1, validationDataTypeOnExtension);
        awaitOneSecond();

        DSSDocument doubleLTADoc = service.extendDocument(extendedDocument, extendParameters);

        // doubleLTADoc.save("target/doubleLTA.xml");

        checkOnSigned(doubleLTADoc, 2, validationDataTypeOnExtension);

        validator = SignedDocumentValidator.fromDocument(doubleLTADoc);
        validator.setCertificateVerifier(getOfflineCertificateVerifier());
        validator.setDetachedContents(Collections.singletonList(documentToSign));
        reports = validator.validateDocument();

        // reports.print();

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

        assertEquals(3, diagnosticData.getTimestampList().size());
        TimestampWrapper signatureTst = diagnosticData.getTimestampList().get(0);
        TimestampWrapper firstArchiveTst = diagnosticData.getTimestampList().get(1);
        TimestampWrapper secondArchiveTst = diagnosticData.getTimestampList().get(2);

        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());

        List<TimestampWrapper> timestampedTimestamps = secondArchiveTst.getTimestampedTimestamps();
        assertEquals(2, timestampedTimestamps.size());
        assertEquals(signatureTst.getId(), timestampedTimestamps.get(0).getId());
        assertEquals(firstArchiveTst.getId(), timestampedTimestamps.get(1).getId());

        List<CertificateWrapper> timestampedCertificates = secondArchiveTst.getTimestampedCertificates();
        List<String> timestampedCertIds = timestampedCertificates.stream().map(CertificateWrapper::getId).collect(Collectors.toList());
        for (CertificateWrapper certificateWrapper : signature.foundCertificates().getRelatedCertificates()) {
            assertTrue(timestampedCertIds.contains(certificateWrapper.getId()));
        }
        for (CertificateWrapper certificateWrapper : signatureTst.foundCertificates().getRelatedCertificates()) {
            assertTrue(timestampedCertIds.contains(certificateWrapper.getId()));
        }
        for (CertificateWrapper certificateWrapper : firstArchiveTst.foundCertificates().getRelatedCertificates()) {
            assertTrue(timestampedCertIds.contains(certificateWrapper.getId()));
        }

        assertEquals(0, firstArchiveTst.foundRevocations().getRelatedRevocationData().size());
        List<RelatedRevocationWrapper> timestampValidationDataRevocations = signature
                .foundRevocations().getRelatedRevocationData();
        assertTrue(Utils.isCollectionNotEmpty(timestampValidationDataRevocations));

        List<RevocationWrapper> timestampedRevocations = secondArchiveTst.getTimestampedRevocations();
        assertEquals(timestampValidationDataRevocations.size(), timestampedRevocations.size());

        List<String> timestampedRevocationIds = timestampedRevocations.stream().map(RevocationWrapper::getId).collect(Collectors.toList());
        for (RevocationWrapper revocationWrapper : timestampValidationDataRevocations) {
            assertTrue(timestampedRevocationIds.contains(revocationWrapper.getId()));
        }
    }

    @Override
    protected CertificateVerifier getCompleteCertificateVerifier() {
        // no cache
        CertificateVerifier certificateVerifier = super.getCompleteCertificateVerifier();
        certificateVerifier.setCrlSource(pkiCRLSource());
        certificateVerifier.setOcspSource(pkiDelegatedOCSPSource());
        return certificateVerifier;
    }

    private void checkOnSigned(DSSDocument document, int expectedArcTsts, ValidationDataEncapsulationStrategy validationDataEncapsulationStrategy) {
        assertTrue(DomUtils.isDOM(document));

        Document documentDom = DomUtils.buildDOM(document);
        NodeList signaturesList = DSSXMLUtils.getAllSignaturesExceptCounterSignatures(documentDom);
        assertEquals(1, signaturesList.getLength());

        XAdES132Path paths = new XAdES132Path();

        Node signature = signaturesList.item(0);

        int certificateValuesCounter = 0;
        int revocationValuesCounter = 0;
        int archiveTimeStampCounter = 0;
        int timeStampValidationDataCounter = 0;
        int anyValidationDataCounter = 0;

        NodeList certificateValuesList = DomUtils.getNodeList(signature, paths.getCertificateValuesPath());
        if (certificateValuesList != null && certificateValuesList.getLength() > 0) {
            certificateValuesCounter = certificateValuesList.getLength();
        }
        NodeList revocationValuesList = DomUtils.getNodeList(signature, paths.getRevocationValuesPath());
        if (revocationValuesList != null && revocationValuesList.getLength() > 0) {
            revocationValuesCounter = revocationValuesList.getLength();
        }
        NodeList archiveTstList = DomUtils.getNodeList(signature, paths.getArchiveTimestampPath());
        if (archiveTstList != null && archiveTstList.getLength() > 0) {
            archiveTimeStampCounter = archiveTstList.getLength();
        }
        NodeList tstVDList = DomUtils.getNodeList(signature, paths.getTimestampValidationDataPath());
        if (tstVDList != null && tstVDList.getLength() > 0) {
            timeStampValidationDataCounter = tstVDList.getLength();
        }
        NodeList anyVDList = DomUtils.getNodeList(signature, paths.getAnyValidationDataRevocationValuesPath());
        if (anyVDList != null && anyVDList.getLength() > 0) {
            anyValidationDataCounter = anyVDList.getLength();
        }

        assertEquals(getExpectedCertificateValuesNumber(validationDataEncapsulationStrategy), certificateValuesCounter);
        assertEquals(getExpectedRevocationValuesNumber(validationDataEncapsulationStrategy), revocationValuesCounter);
        assertEquals(expectedArcTsts, archiveTimeStampCounter);
        assertEquals(getExpectedTimeStampValidationDataNumber(validationDataEncapsulationStrategy, expectedArcTsts), timeStampValidationDataCounter);
        assertEquals(getExpectedAnyValidationDataNumber(validationDataEncapsulationStrategy, expectedArcTsts), anyValidationDataCounter);
    }

    private int getExpectedCertificateValuesNumber(ValidationDataEncapsulationStrategy validationDataEncapsulationStrategy) {
        switch (validationDataEncapsulationStrategy) {
            case CERTIFICATE_REVOCATION_VALUES_AND_ANY_VALIDATION_DATA:
            case CERTIFICATE_REVOCATION_VALUES_AND_TIMESTAMP_VALIDATION_DATA:
            case CERTIFICATE_REVOCATION_VALUES_AND_TIMESTAMP_VALIDATION_DATA_LT_SEPARATED:
            case CERTIFICATE_REVOCATION_VALUES_AND_TIMESTAMP_VALIDATION_DATA_AND_ANY_VALIDATION_DATA:
                return 1;
            case ANY_VALIDATION_DATA_ONLY:
                return 0;
            default:
                fail(String.format("Not supported type %s", validationDataEncapsulationStrategy));
                return -1;
        }
    }

    private int getExpectedRevocationValuesNumber(ValidationDataEncapsulationStrategy validationDataEncapsulationStrategy) {
        switch (validationDataEncapsulationStrategy) {
            case CERTIFICATE_REVOCATION_VALUES_AND_ANY_VALIDATION_DATA:
            case CERTIFICATE_REVOCATION_VALUES_AND_TIMESTAMP_VALIDATION_DATA:
            case CERTIFICATE_REVOCATION_VALUES_AND_TIMESTAMP_VALIDATION_DATA_LT_SEPARATED:
            case CERTIFICATE_REVOCATION_VALUES_AND_TIMESTAMP_VALIDATION_DATA_AND_ANY_VALIDATION_DATA:
                return 1;
            case ANY_VALIDATION_DATA_ONLY:
                return 0;
            default:
                fail(String.format("Not supported type %s", validationDataEncapsulationStrategy));
                return -1;
        }
    }

    private int getExpectedTimeStampValidationDataNumber(ValidationDataEncapsulationStrategy validationDataEncapsulationStrategy, int expectedArcTsts) {
        switch (validationDataEncapsulationStrategy) {
            case CERTIFICATE_REVOCATION_VALUES_AND_TIMESTAMP_VALIDATION_DATA:
                return expectedArcTsts > 0 ? expectedArcTsts - 1 : 0;
            case CERTIFICATE_REVOCATION_VALUES_AND_TIMESTAMP_VALIDATION_DATA_LT_SEPARATED:
            case CERTIFICATE_REVOCATION_VALUES_AND_TIMESTAMP_VALIDATION_DATA_AND_ANY_VALIDATION_DATA:
                return expectedArcTsts > 0 ? expectedArcTsts : 1;
            case CERTIFICATE_REVOCATION_VALUES_AND_ANY_VALIDATION_DATA:
            case ANY_VALIDATION_DATA_ONLY:
                return 0;
            default:
                fail(String.format("Not supported type %s", validationDataEncapsulationStrategy));
                return -1;
        }
    }

    private int getExpectedAnyValidationDataNumber(ValidationDataEncapsulationStrategy validationDataEncapsulationStrategy, int expectedArcTsts) {
        switch (validationDataEncapsulationStrategy) {
            case CERTIFICATE_REVOCATION_VALUES_AND_TIMESTAMP_VALIDATION_DATA:
            case CERTIFICATE_REVOCATION_VALUES_AND_TIMESTAMP_VALIDATION_DATA_LT_SEPARATED:
                return 0;
            case CERTIFICATE_REVOCATION_VALUES_AND_TIMESTAMP_VALIDATION_DATA_AND_ANY_VALIDATION_DATA:
                return expectedArcTsts > 0 ? expectedArcTsts - 1 : 0;
            case CERTIFICATE_REVOCATION_VALUES_AND_ANY_VALIDATION_DATA:
            case ANY_VALIDATION_DATA_ONLY:
                return expectedArcTsts > 0 ? expectedArcTsts : 1;
            default:
                fail(String.format("Not supported type %s", validationDataEncapsulationStrategy));
                return -1;
        }
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

    private void checkValidationDataOriginsOnSignature(DiagnosticData diagnosticData, ValidationDataEncapsulationStrategy validationDataEncapsulationStrategy) {
        switch (validationDataEncapsulationStrategy) {
            case CERTIFICATE_REVOCATION_VALUES_AND_TIMESTAMP_VALIDATION_DATA:
                assertContainsCertificatesOfOrigin(diagnosticData, CertificateOrigin.KEY_INFO, CertificateOrigin.CERTIFICATE_VALUES);
                assertContainsRevocationOfOrigin(diagnosticData, RevocationOrigin.REVOCATION_VALUES);
                break;
            case CERTIFICATE_REVOCATION_VALUES_AND_TIMESTAMP_VALIDATION_DATA_LT_SEPARATED:
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
                fail(String.format("Not supported type %s", validationDataEncapsulationStrategy));
        }
    }

    private void checkValidationDataOriginsOnExtension(DiagnosticData diagnosticData, ValidationDataEncapsulationStrategy validationDataEncapsulationStrategy) {
        switch (validationDataEncapsulationStrategy) {
            case CERTIFICATE_REVOCATION_VALUES_AND_TIMESTAMP_VALIDATION_DATA:
            case CERTIFICATE_REVOCATION_VALUES_AND_TIMESTAMP_VALIDATION_DATA_LT_SEPARATED:
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
                fail(String.format("Not supported type %s", validationDataEncapsulationStrategy));
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
