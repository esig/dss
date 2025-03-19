package eu.europa.esig.dss.validation.executor.process;

import eu.europa.esig.dss.detailedreport.DetailedReport;
import eu.europa.esig.dss.detailedreport.jaxb.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSAV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.diagnostic.DiagnosticDataFacade;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificate;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificateRef;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestAlgoAndValue;
import eu.europa.esig.dss.diagnostic.jaxb.XmlFoundCertificates;
import eu.europa.esig.dss.diagnostic.jaxb.XmlRelatedCertificate;
import eu.europa.esig.dss.enumerations.CertificateOrigin;
import eu.europa.esig.dss.enumerations.CertificateRefOrigin;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.ValidationPolicy;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.simplereport.jaxb.XmlTimestamp;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.executor.signature.DefaultSignatureProcessExecutor;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.validationreport.enums.ObjectType;
import eu.europa.esig.validationreport.jaxb.CryptoInformationType;
import eu.europa.esig.validationreport.jaxb.SignatureValidationReportType;
import eu.europa.esig.validationreport.jaxb.ValidationObjectListType;
import eu.europa.esig.validationreport.jaxb.ValidationObjectType;
import eu.europa.esig.validationreport.jaxb.ValidationReportDataType;
import eu.europa.esig.validationreport.jaxb.ValidationReportType;
import eu.europa.esig.validationreport.jaxb.ValidationStatusType;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DSS3575ExecutorTest extends AbstractProcessExecutorTest {

    @Test
    void dss3575Test() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/diag-data/diag_data_sha1_sign_cert.xml"));
        assertNotNull(diagnosticData);

        ValidationPolicy validationPolicy = loadDefaultPolicy();

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);
        validationPolicy.getTimestampConstraints().getSignedAttributes().setSigningCertificateDigestAlgorithm(constraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();
        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));

        DetailedReport detailedReport = reports.getDetailedReport();
        for (XmlTimestamp xmlTimestamp : simpleReport.getSignatureTimestamps(simpleReport.getFirstSignatureId())) {
            assertEquals(Indication.PASSED, xmlTimestamp.getIndication());

            XmlBasicBuildingBlocks tstBBB = detailedReport.getBasicBuildingBlockById(xmlTimestamp.getId());
            assertNotNull(tstBBB);

            XmlSAV xmlSAV = tstBBB.getSAV();
            assertNotNull(xmlSAV);

            int signCertRefCheckCounter = 0;
            for (XmlConstraint xmlConstraint : xmlSAV.getConstraint()) {
                if (i18nProvider.getMessage(MessageTag.ACCM, MessageTag.ACCM_POS_SIG_CERT_REF).equals(xmlConstraint.getName().getValue())) {
                    assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                    ++signCertRefCheckCounter;
                }
            }
            assertEquals(1, signCertRefCheckCounter);
        }

        ValidationReportType validationReportJaxb = reports.getEtsiValidationReportJaxb();
        assertNotNull(validationReportJaxb);

        ValidationObjectListType validationObjectsType = validationReportJaxb.getSignatureValidationObjects();
        assertNotNull(validationObjectsType);

        List<ValidationObjectType> validationObjects = validationObjectsType.getValidationObject();
        assertTrue(Utils.isCollectionNotEmpty(validationObjects));

        boolean sha3With384TstFound = false;
        boolean sha3With512TstFound = false;
        for (ValidationObjectType validationObject : validationObjects) {
            if (ObjectType.TIMESTAMP == validationObject.getObjectType()) {
                SignatureValidationReportType validationReport = validationObject.getValidationReport();
                assertNotNull(validationReport);

                ValidationStatusType signatureValidationStatus = validationReport.getSignatureValidationStatus();
                assertNotNull(signatureValidationStatus);

                List<ValidationReportDataType> associatedValidationReportData = signatureValidationStatus.getAssociatedValidationReportData();
                assertTrue(Utils.isCollectionNotEmpty(validationObjects));

                for (ValidationReportDataType validationReportData : associatedValidationReportData) {
                    CryptoInformationType cryptoInformation = validationReportData.getCryptoInformation();
                    if (cryptoInformation != null) {
                        assertTrue(cryptoInformation.isSecureAlgorithm());
                        assertNull(cryptoInformation.getNotAfter());
                        assertNotNull(cryptoInformation.getAlgorithm());

                        SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.forXML(cryptoInformation.getAlgorithm());
                        assertNotNull(signatureAlgorithm);

                        if (DigestAlgorithm.SHA3_384 == signatureAlgorithm.getDigestAlgorithm()) {
                            sha3With384TstFound = true;
                        } else if (DigestAlgorithm.SHA3_512 == signatureAlgorithm.getDigestAlgorithm()) {
                            sha3With512TstFound = true;
                        }

                    }
                }
            }
        }
        assertTrue(sha3With384TstFound);
        assertTrue(sha3With512TstFound);

        checkReports(reports);
    }

    @Test
    void dss3575Sha1OnlyTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/diag-data/diag_data_sha1_sign_cert.xml"));
        assertNotNull(diagnosticData);

        for (eu.europa.esig.dss.diagnostic.jaxb.XmlTimestamp xmlTimestamp : diagnosticData.getUsedTimestamps()) {
            XmlFoundCertificates foundCertificates = xmlTimestamp.getFoundCertificates();
            for (XmlRelatedCertificate xmlRelatedCertificate : foundCertificates.getRelatedCertificates()) {
                xmlRelatedCertificate.getCertificateRefs().removeIf(xmlCertificateRef ->
                        CertificateRefOrigin.SIGNING_CERTIFICATE == xmlCertificateRef.getOrigin()
                                && DigestAlgorithm.SHA1 != xmlCertificateRef.getDigestAlgoAndValue().getDigestMethod());
            }
        }

        ValidationPolicy validationPolicy = loadDefaultPolicy();

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);
        validationPolicy.getTimestampConstraints().getSignedAttributes().setSigningCertificateDigestAlgorithm(constraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();
        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));

        DetailedReport detailedReport = reports.getDetailedReport();
        for (XmlTimestamp xmlTimestamp : simpleReport.getSignatureTimestamps(simpleReport.getFirstSignatureId())) {
            assertEquals(Indication.INDETERMINATE, xmlTimestamp.getIndication());
            assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, xmlTimestamp.getSubIndication());

            XmlBasicBuildingBlocks tstBBB = detailedReport.getBasicBuildingBlockById(xmlTimestamp.getId());
            assertNotNull(tstBBB);

            XmlSAV xmlSAV = tstBBB.getSAV();
            assertNotNull(xmlSAV);

            int signCertRefCheckCounter = 0;
            for (XmlConstraint xmlConstraint : xmlSAV.getConstraint()) {
                if (i18nProvider.getMessage(MessageTag.ACCM, MessageTag.ACCM_POS_SIG_CERT_REF).equals(xmlConstraint.getName().getValue())) {
                    assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                    ++signCertRefCheckCounter;
                }
            }
            assertEquals(1, signCertRefCheckCounter);
        }

        ValidationReportType validationReportJaxb = reports.getEtsiValidationReportJaxb();
        assertNotNull(validationReportJaxb);

        ValidationObjectListType validationObjectsType = validationReportJaxb.getSignatureValidationObjects();
        assertNotNull(validationObjectsType);

        List<ValidationObjectType> validationObjects = validationObjectsType.getValidationObject();
        assertTrue(Utils.isCollectionNotEmpty(validationObjects));

        int sha1TstCounter = 0;
        int noSha1TstCounter = 0;
        for (ValidationObjectType validationObject : validationObjects) {
            if (ObjectType.TIMESTAMP == validationObject.getObjectType()) {
                SignatureValidationReportType validationReport = validationObject.getValidationReport();
                assertNotNull(validationReport);

                ValidationStatusType signatureValidationStatus = validationReport.getSignatureValidationStatus();
                assertNotNull(signatureValidationStatus);

                List<ValidationReportDataType> associatedValidationReportData = signatureValidationStatus.getAssociatedValidationReportData();
                assertTrue(Utils.isCollectionNotEmpty(validationObjects));

                for (ValidationReportDataType validationReportData : associatedValidationReportData) {
                    CryptoInformationType cryptoInformation = validationReportData.getCryptoInformation();
                    if (cryptoInformation != null) {
                        assertFalse(cryptoInformation.isSecureAlgorithm());
                        assertNotNull(cryptoInformation.getNotAfter());
                        assertNotNull(cryptoInformation.getAlgorithm());

                        DigestAlgorithm digestAlgorithm = DigestAlgorithm.forXML(cryptoInformation.getAlgorithm());
                        assertNotNull(digestAlgorithm);
                        if (DigestAlgorithm.SHA1 == digestAlgorithm) {
                            ++sha1TstCounter;
                        } else {
                            ++noSha1TstCounter;
                        }

                    }
                }
            }
        }
        assertEquals(2, sha1TstCounter);
        assertEquals(0, noSha1TstCounter);

        checkReports(reports);
    }

    @Test
    void dss3575WithCACertTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/diag-data/diag_data_sha1_sign_cert.xml"));
        assertNotNull(diagnosticData);

        for (eu.europa.esig.dss.diagnostic.jaxb.XmlTimestamp xmlTimestamp : diagnosticData.getUsedTimestamps()) {
            XmlCertificate tstCACertificate = xmlTimestamp.getSigningCertificate().getCertificate()
                    .getSigningCertificate().getCertificate();

            XmlFoundCertificates foundCertificates = xmlTimestamp.getFoundCertificates();
            XmlRelatedCertificate xmlRelatedCertificate = new XmlRelatedCertificate();
            xmlRelatedCertificate.setCertificate(tstCACertificate);
            xmlRelatedCertificate.getOrigins().add(CertificateOrigin.SIGNED_DATA);

            XmlCertificateRef xmlCertificateRef = new XmlCertificateRef();
            XmlDigestAlgoAndValue digestAlgoAndValue = new XmlDigestAlgoAndValue();
            digestAlgoAndValue.setDigestMethod(DigestAlgorithm.SHA3_256);
            digestAlgoAndValue.setMatch(true);
            xmlCertificateRef.setDigestAlgoAndValue(digestAlgoAndValue);
            xmlCertificateRef.setOrigin(CertificateRefOrigin.SIGNING_CERTIFICATE);
            xmlRelatedCertificate.getCertificateRefs().add(xmlCertificateRef);

            foundCertificates.getRelatedCertificates().add(xmlRelatedCertificate);
        }

        ValidationPolicy validationPolicy = loadDefaultPolicy();

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);
        validationPolicy.getTimestampConstraints().getSignedAttributes().setSigningCertificateDigestAlgorithm(constraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();
        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));

        DetailedReport detailedReport = reports.getDetailedReport();
        for (XmlTimestamp xmlTimestamp : simpleReport.getSignatureTimestamps(simpleReport.getFirstSignatureId())) {
            assertEquals(Indication.PASSED, xmlTimestamp.getIndication());

            XmlBasicBuildingBlocks tstBBB = detailedReport.getBasicBuildingBlockById(xmlTimestamp.getId());
            assertNotNull(tstBBB);

            XmlSAV xmlSAV = tstBBB.getSAV();
            assertNotNull(xmlSAV);

            int signCertRefCheckCounter = 0;
            for (XmlConstraint xmlConstraint : xmlSAV.getConstraint()) {
                if (i18nProvider.getMessage(MessageTag.ACCM, MessageTag.ACCM_POS_SIG_CERT_REF).equals(xmlConstraint.getName().getValue())) {
                    assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                    ++signCertRefCheckCounter;
                }
            }
            assertEquals(2, signCertRefCheckCounter);
        }

        ValidationReportType validationReportJaxb = reports.getEtsiValidationReportJaxb();
        assertNotNull(validationReportJaxb);

        ValidationObjectListType validationObjectsType = validationReportJaxb.getSignatureValidationObjects();
        assertNotNull(validationObjectsType);

        List<ValidationObjectType> validationObjects = validationObjectsType.getValidationObject();
        assertTrue(Utils.isCollectionNotEmpty(validationObjects));

        boolean sha3With384TstFound = false;
        boolean sha3With512TstFound = false;
        for (ValidationObjectType validationObject : validationObjects) {
            if (ObjectType.TIMESTAMP == validationObject.getObjectType()) {
                SignatureValidationReportType validationReport = validationObject.getValidationReport();
                assertNotNull(validationReport);

                ValidationStatusType signatureValidationStatus = validationReport.getSignatureValidationStatus();
                assertNotNull(signatureValidationStatus);

                List<ValidationReportDataType> associatedValidationReportData = signatureValidationStatus.getAssociatedValidationReportData();
                assertTrue(Utils.isCollectionNotEmpty(validationObjects));

                for (ValidationReportDataType validationReportData : associatedValidationReportData) {
                    CryptoInformationType cryptoInformation = validationReportData.getCryptoInformation();
                    if (cryptoInformation != null) {
                        assertTrue(cryptoInformation.isSecureAlgorithm());
                        assertNull(cryptoInformation.getNotAfter());
                        assertNotNull(cryptoInformation.getAlgorithm());

                        SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.forXML(cryptoInformation.getAlgorithm());
                        assertNotNull(signatureAlgorithm);

                        if (DigestAlgorithm.SHA3_384 == signatureAlgorithm.getDigestAlgorithm()) {
                            sha3With384TstFound = true;
                        } else if (DigestAlgorithm.SHA3_512 == signatureAlgorithm.getDigestAlgorithm()) {
                            sha3With512TstFound = true;
                        }

                    }
                }
            }
        }
        assertTrue(sha3With384TstFound);
        assertTrue(sha3With512TstFound);

        checkReports(reports);
    }

    @Test
    void dss3575WithCACertInvalidTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/diag-data/diag_data_sha1_sign_cert.xml"));
        assertNotNull(diagnosticData);

        for (eu.europa.esig.dss.diagnostic.jaxb.XmlTimestamp xmlTimestamp : diagnosticData.getUsedTimestamps()) {
            XmlCertificate tstCACertificate = xmlTimestamp.getSigningCertificate().getCertificate()
                    .getSigningCertificate().getCertificate();

            XmlFoundCertificates foundCertificates = xmlTimestamp.getFoundCertificates();
            XmlRelatedCertificate xmlRelatedCertificate = new XmlRelatedCertificate();
            xmlRelatedCertificate.setCertificate(tstCACertificate);
            xmlRelatedCertificate.getOrigins().add(CertificateOrigin.SIGNED_DATA);

            XmlCertificateRef xmlCertificateRef = new XmlCertificateRef();
            XmlDigestAlgoAndValue digestAlgoAndValue = new XmlDigestAlgoAndValue();
            digestAlgoAndValue.setDigestMethod(DigestAlgorithm.SHA1);
            digestAlgoAndValue.setMatch(true);
            xmlCertificateRef.setDigestAlgoAndValue(digestAlgoAndValue);
            xmlCertificateRef.setOrigin(CertificateRefOrigin.SIGNING_CERTIFICATE);
            xmlRelatedCertificate.getCertificateRefs().add(xmlCertificateRef);

            foundCertificates.getRelatedCertificates().add(xmlRelatedCertificate);
        }

        ValidationPolicy validationPolicy = loadDefaultPolicy();

        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);
        validationPolicy.getTimestampConstraints().getSignedAttributes().setSigningCertificateDigestAlgorithm(constraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();
        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));

        DetailedReport detailedReport = reports.getDetailedReport();
        for (XmlTimestamp xmlTimestamp : simpleReport.getSignatureTimestamps(simpleReport.getFirstSignatureId())) {
            assertEquals(Indication.INDETERMINATE, xmlTimestamp.getIndication());
            assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, xmlTimestamp.getSubIndication());

            XmlBasicBuildingBlocks tstBBB = detailedReport.getBasicBuildingBlockById(xmlTimestamp.getId());
            assertNotNull(tstBBB);

            XmlSAV xmlSAV = tstBBB.getSAV();
            assertNotNull(xmlSAV);

            int signCertRefCheckInvalidCounter = 0;
            for (XmlConstraint xmlConstraint : xmlSAV.getConstraint()) {
                if (i18nProvider.getMessage(MessageTag.ACCM, MessageTag.ACCM_POS_SIG_CERT_REF).equals(xmlConstraint.getName().getValue())) {
                    if (XmlStatus.NOT_OK == xmlConstraint.getStatus()) {
                        ++signCertRefCheckInvalidCounter;
                    }
                }
            }
            assertEquals(1, signCertRefCheckInvalidCounter);
        }

        ValidationReportType validationReportJaxb = reports.getEtsiValidationReportJaxb();
        assertNotNull(validationReportJaxb);

        ValidationObjectListType validationObjectsType = validationReportJaxb.getSignatureValidationObjects();
        assertNotNull(validationObjectsType);

        List<ValidationObjectType> validationObjects = validationObjectsType.getValidationObject();
        assertTrue(Utils.isCollectionNotEmpty(validationObjects));

        int sha1TstCounter = 0;
        int noSha1TstCounter = 0;
        for (ValidationObjectType validationObject : validationObjects) {
            if (ObjectType.TIMESTAMP == validationObject.getObjectType()) {
                SignatureValidationReportType validationReport = validationObject.getValidationReport();
                assertNotNull(validationReport);

                ValidationStatusType signatureValidationStatus = validationReport.getSignatureValidationStatus();
                assertNotNull(signatureValidationStatus);

                List<ValidationReportDataType> associatedValidationReportData = signatureValidationStatus.getAssociatedValidationReportData();
                assertTrue(Utils.isCollectionNotEmpty(validationObjects));

                for (ValidationReportDataType validationReportData : associatedValidationReportData) {
                    CryptoInformationType cryptoInformation = validationReportData.getCryptoInformation();
                    if (cryptoInformation != null) {
                        assertFalse(cryptoInformation.isSecureAlgorithm());
                        assertNotNull(cryptoInformation.getNotAfter());
                        assertNotNull(cryptoInformation.getAlgorithm());

                        DigestAlgorithm digestAlgorithm = DigestAlgorithm.forXML(cryptoInformation.getAlgorithm());
                        assertNotNull(digestAlgorithm);
                        if (DigestAlgorithm.SHA1 == digestAlgorithm) {
                            ++sha1TstCounter;
                        } else {
                            ++noSha1TstCounter;
                        }

                    }
                }
            }
        }
        assertEquals(2, sha1TstCounter);
        assertEquals(0, noSha1TstCounter);

        checkReports(reports);
    }

}
