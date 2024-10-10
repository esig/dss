package eu.europa.esig.dss.validation.executor.process;

import eu.europa.esig.dss.detailedreport.DetailedReport;
import eu.europa.esig.dss.detailedreport.jaxb.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlFC;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.diagnostic.DiagnosticDataFacade;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlByteRange;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDocMDP;
import eu.europa.esig.dss.diagnostic.jaxb.XmlObjectModification;
import eu.europa.esig.dss.diagnostic.jaxb.XmlObjectModifications;
import eu.europa.esig.dss.diagnostic.jaxb.XmlPDFLockDictionary;
import eu.europa.esig.dss.diagnostic.jaxb.XmlPDFRevision;
import eu.europa.esig.dss.diagnostic.jaxb.XmlPDFSignatureDictionary;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignature;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTimestamp;
import eu.europa.esig.dss.enumerations.CertificationPermission;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.PdfLockAction;
import eu.europa.esig.dss.enumerations.PdfObjectModificationType;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.enumerations.ValidationLevel;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.jaxb.object.Message;
import eu.europa.esig.dss.policy.EtsiValidationPolicy;
import eu.europa.esig.dss.policy.ValidationPolicy;
import eu.europa.esig.dss.policy.ValidationPolicyFacade;
import eu.europa.esig.dss.policy.jaxb.BasicSignatureConstraints;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.policy.jaxb.SignatureConstraints;
import eu.europa.esig.dss.policy.jaxb.SignedAttributesConstraints;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.executor.signature.DefaultSignatureProcessExecutor;
import eu.europa.esig.dss.validation.reports.Reports;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PDFValidationExecutorTest extends AbstractProcessExecutorTest {

    @Test
    void testPdfSignatureDictionary() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/diag-data/diag_data_pdfsigdict.xml"));
        assertNotNull(xmlDiagnosticData);

        List<XmlSignature> xmlSignatures = xmlDiagnosticData.getSignatures();
        assertNotNull(xmlSignatures);
        for (eu.europa.esig.dss.diagnostic.jaxb.XmlSignature signature : xmlSignatures) {
            XmlPDFRevision pdfRevision = signature.getPDFRevision();
            assertNotNull(pdfRevision);
            XmlPDFSignatureDictionary pdfSignatureDictionary = pdfRevision.getPDFSignatureDictionary();
            assertNotNull(pdfSignatureDictionary);
            List<BigInteger> byteRange = pdfSignatureDictionary.getSignatureByteRange().getValue();
            assertNotNull(byteRange);
            assertEquals(4, byteRange.size());
            assertEquals(-1, byteRange.get(1).compareTo(byteRange.get(2)));
        }

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(loadTLPolicy());
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();
        assertNotNull(reports);
        eu.europa.esig.dss.diagnostic.DiagnosticData diagnosticData = reports.getDiagnosticData();
        assertNotNull(diagnosticData.getAllSignatures());
        SignatureWrapper signatureWrapper = diagnosticData.getSignatureById(xmlSignatures.get(0).getId());
        assertNotNull(signatureWrapper);
        List<BigInteger> byteRange = signatureWrapper.getSignatureByteRange();
        assertNotNull(byteRange);
        assertEquals(4, byteRange.size());
        List<BigInteger> xmlByteRange = xmlSignatures.get(0).getPDFRevision().getPDFSignatureDictionary().getSignatureByteRange().getValue();
        assertEquals(xmlByteRange.get(0), byteRange.get(0));
        assertEquals(xmlByteRange.get(1), byteRange.get(1));
        assertEquals(xmlByteRange.get(2), byteRange.get(2));
        assertEquals(xmlByteRange.get(3), byteRange.get(3));

        checkReports(reports);
    }

    @Test
    void padesMultiSignerInfoPresentTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/diag-data/pades-multi-signer-info.xml"));
        assertNotNull(diagnosticData);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_FAILED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.FORMAT_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));

        DetailedReport detailedReport = reports.getDetailedReport();
        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertNotNull(signatureBBB);

        XmlFC fc = signatureBBB.getFC();
        assertEquals(Indication.FAILED, fc.getConclusion().getIndication());
        assertEquals(SubIndication.FORMAT_FAILURE, fc.getConclusion().getSubIndication());

        boolean signerInformationCheckFound = false;
        List<XmlConstraint> constraints = fc.getConstraint();
        for (XmlConstraint constrant : constraints) {
            if (MessageTag.BBB_FC_IOSIP.name().equals(constrant.getName().getKey())) {
                assertEquals(MessageTag.BBB_FC_IOSIP_ANS.name(), constrant.getError().getKey());
                assertEquals(XmlStatus.NOT_OK, constrant.getStatus());
                signerInformationCheckFound = true;
            }
        }
        assertTrue(signerInformationCheckFound);
    }

    @Test
    void padesMultiSignerInfoPresentWarnTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/diag-data/pades-multi-signer-info.xml"));
        assertNotNull(diagnosticData);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        EtsiValidationPolicy defaultPolicy = (EtsiValidationPolicy) ValidationPolicyFacade.newFacade().getDefaultValidationPolicy();
        BasicSignatureConstraints basicSignatureConstraints = defaultPolicy.getSignatureConstraints().getBasicSignatureConstraints();
        LevelConstraint signerInformationStore = basicSignatureConstraints.getSignerInformationStore();
        signerInformationStore.setLevel(Level.WARN);
        executor.setValidationPolicy(defaultPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));

        List<Message> warnings = simpleReport.getAdESValidationWarnings(simpleReport.getFirstSignatureId());
        assertTrue(checkMessageValuePresence(warnings,
                i18nProvider.getMessage(MessageTag.BBB_FC_IOSIP_ANS)));
    }

    @Test
    void padesFieldsOverlappingFailTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/diag-data/diag_data_pdf_fields_overlap.xml"));
        assertNotNull(diagnosticData);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        EtsiValidationPolicy defaultPolicy = (EtsiValidationPolicy) ValidationPolicyFacade.newFacade().getDefaultValidationPolicy();
        BasicSignatureConstraints basicSignatureConstraints = defaultPolicy.getSignatureConstraints().getBasicSignatureConstraints();
        LevelConstraint pdfAnnotationOverlap = basicSignatureConstraints.getPdfAnnotationOverlap();
        pdfAnnotationOverlap.setLevel(Level.FAIL);
        executor.setValidationPolicy(defaultPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        for (String signatureId : simpleReport.getSignatureIdList()) {
            assertEquals(Indication.TOTAL_FAILED, simpleReport.getIndication(signatureId));
            assertEquals(SubIndication.FORMAT_FAILURE, simpleReport.getSubIndication(signatureId));

            List<Message> errors = simpleReport.getAdESValidationErrors(signatureId);
            assertTrue(checkMessageValuePresence(errors,
                    i18nProvider.getMessage(MessageTag.BBB_FC_IAOD_ANS, "[1]")));
        }
    }

    @Test
    void padesFieldsOverlappingWarnTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/diag-data/diag_data_pdf_fields_overlap.xml"));
        assertNotNull(diagnosticData);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        EtsiValidationPolicy defaultPolicy = (EtsiValidationPolicy) ValidationPolicyFacade.newFacade().getDefaultValidationPolicy();
        BasicSignatureConstraints basicSignatureConstraints = defaultPolicy.getSignatureConstraints().getBasicSignatureConstraints();
        LevelConstraint pdfAnnotationOverlap = basicSignatureConstraints.getPdfAnnotationOverlap();
        pdfAnnotationOverlap.setLevel(Level.WARN);
        executor.setValidationPolicy(defaultPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        for (String signatureId : simpleReport.getSignatureIdList()) {
            assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(signatureId));

            List<Message> warnings = simpleReport.getAdESValidationWarnings(signatureId);
            assertTrue(checkMessageValuePresence(warnings,
                    i18nProvider.getMessage(MessageTag.BBB_FC_IAOD_ANS, "[1]")));
        }
    }

    @Test
    void padesVisualDifferenceFailTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/diag-data/diag_data_pdf_visual_difference.xml"));
        assertNotNull(diagnosticData);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        EtsiValidationPolicy defaultPolicy = (EtsiValidationPolicy) ValidationPolicyFacade.newFacade().getDefaultValidationPolicy();
        BasicSignatureConstraints basicSignatureConstraints = defaultPolicy.getSignatureConstraints().getBasicSignatureConstraints();
        LevelConstraint pdfVisualDifference = basicSignatureConstraints.getPdfVisualDifference();
        pdfVisualDifference.setLevel(Level.FAIL);
        executor.setValidationPolicy(defaultPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        for (String signatureId : simpleReport.getSignatureIdList()) {
            assertEquals(Indication.TOTAL_FAILED, simpleReport.getIndication(signatureId));
            assertEquals(SubIndication.FORMAT_FAILURE, simpleReport.getSubIndication(signatureId));

            List<Message> errors = simpleReport.getAdESValidationErrors(signatureId);
            assertTrue(checkMessageValuePresence(errors,
                    i18nProvider.getMessage(MessageTag.BBB_FC_IVDBSFR_ANS, "[1]")));
        }
    }

    @Test
    void padesVisualDifferenceWarnTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/diag-data/diag_data_pdf_visual_difference.xml"));
        assertNotNull(diagnosticData);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        EtsiValidationPolicy defaultPolicy = (EtsiValidationPolicy) ValidationPolicyFacade.newFacade().getDefaultValidationPolicy();
        BasicSignatureConstraints basicSignatureConstraints = defaultPolicy.getSignatureConstraints().getBasicSignatureConstraints();
        LevelConstraint pdfVisualDifference = basicSignatureConstraints.getPdfVisualDifference();
        pdfVisualDifference.setLevel(Level.WARN);
        executor.setValidationPolicy(defaultPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        for (String signatureId : simpleReport.getSignatureIdList()) {
            assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(signatureId));

            List<Message> warnings = simpleReport.getAdESValidationWarnings(signatureId);
            assertTrue(checkMessageValuePresence(warnings,
                    i18nProvider.getMessage(MessageTag.BBB_FC_IVDBSFR_ANS, "[1]")));
        }
    }

    @Test
    void padesDoubleLtaTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade()
                .unmarshall(new File("src/test/resources/diag-data/diag_data_pades_double_lta.xml"));
        assertNotNull(diagnosticData);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        executor.setValidationLevel(ValidationLevel.BASIC_SIGNATURES);
        Reports reports = executor.execute();
        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(diagnosticData.getValidationDate(),
                simpleReport.getBestSignatureTime(simpleReport.getFirstSignatureId()));

        executor.setValidationLevel(ValidationLevel.LONG_TERM_DATA);
        reports = executor.execute();
        simpleReport = reports.getSimpleReport();
        assertEquals(diagnosticData.getUsedTimestamps().get(1).getProductionTime(),
                simpleReport.getBestSignatureTime(simpleReport.getFirstSignatureId()));

        executor.setValidationLevel(ValidationLevel.ARCHIVAL_DATA);
        reports = executor.execute();
        simpleReport = reports.getSimpleReport();
        assertEquals(diagnosticData.getUsedTimestamps().get(0).getProductionTime(),
                simpleReport.getBestSignatureTime(simpleReport.getFirstSignatureId()));
    }

    @Test
    void padesDocSigTstTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade()
                .unmarshall(new File("src/test/resources/diag-data/diag_data_pades_doc_sig_tst.xml"));
        assertNotNull(diagnosticData);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        executor.setValidationLevel(ValidationLevel.BASIC_SIGNATURES);
        Reports reports = executor.execute();
        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(diagnosticData.getValidationDate(),
                simpleReport.getBestSignatureTime(simpleReport.getFirstSignatureId()));

        executor.setValidationLevel(ValidationLevel.LONG_TERM_DATA);
        reports = executor.execute();
        simpleReport = reports.getSimpleReport();
        assertEquals(diagnosticData.getUsedTimestamps().get(0).getProductionTime(),
                simpleReport.getBestSignatureTime(simpleReport.getFirstSignatureId()));

        executor.setValidationLevel(ValidationLevel.ARCHIVAL_DATA);
        reports = executor.execute();
        simpleReport = reports.getSimpleReport();
        assertEquals(diagnosticData.getUsedTimestamps().get(0).getProductionTime(),
                simpleReport.getBestSignatureTime(simpleReport.getFirstSignatureId()));
    }

    @Test
    void padesDocMissingRevocDataTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade()
                .unmarshall(new File("src/test/resources/diag-data/diag_data_pades_doc_sig_tst.xml"));
        assertNotNull(diagnosticData);

        // remove revocations
        diagnosticData.getSignatures().get(0).getSigningCertificate().getCertificate().getRevocations().clear();

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        executor.setValidationLevel(ValidationLevel.BASIC_SIGNATURES);
        Reports reports = executor.execute();
        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(diagnosticData.getValidationDate(),
                simpleReport.getBestSignatureTime(simpleReport.getFirstSignatureId()));

        // best-signature-time is not calculated as basic signature validation fails
        executor.setValidationLevel(ValidationLevel.LONG_TERM_DATA);
        reports = executor.execute();
        simpleReport = reports.getSimpleReport();
        assertEquals(diagnosticData.getValidationDate(),
                simpleReport.getBestSignatureTime(simpleReport.getFirstSignatureId()));

        executor.setValidationLevel(ValidationLevel.ARCHIVAL_DATA);
        reports = executor.execute();
        simpleReport = reports.getSimpleReport();
        assertEquals(diagnosticData.getValidationDate(),
                simpleReport.getBestSignatureTime(simpleReport.getFirstSignatureId()));
    }

    @Test
    void pkcs7Test() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_pkcs7.xml"));
        assertNotNull(xmlDiagnosticData);

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        SignatureConstraints signatureConstraints = validationPolicy.getSignatureConstraints();
        SignedAttributesConstraints signedAttributes = signatureConstraints.getSignedAttributes();
        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.WARN);
        signedAttributes.setSigningCertificatePresent(levelConstraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId())));
        assertEquals(1, simpleReport.getAdESValidationWarnings(simpleReport.getFirstSignatureId()).size());
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationWarnings(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_ICS_ISASCP_ANS)));
    }

    @Test
    void docMDPTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_with_object_modifications.xml"));
        assertNotNull(xmlDiagnosticData);

        XmlSignature xmlSignature = xmlDiagnosticData.getSignatures().get(0);
        XmlPDFSignatureDictionary pdfSignatureDictionary = xmlSignature.getPDFRevision().getPDFSignatureDictionary();

        XmlDocMDP xmlDocMDP = new XmlDocMDP();
        xmlDocMDP.setPermissions(CertificationPermission.NO_CHANGE_PERMITTED);
        pdfSignatureDictionary.setDocMDP(xmlDocMDP);

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.FAIL);
        validationPolicy.getSignatureConstraints().getBasicSignatureConstraints().setDocMDP(levelConstraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();
        SimpleReport simpleReport = reports.getSimpleReport();

        boolean certificationSigFound = false;
        boolean secondSigFound = false;
        for (String sigId : simpleReport.getSignatureIdList()) {
            if (Indication.TOTAL_FAILED.equals(simpleReport.getIndication(sigId))) {
                assertEquals(SubIndication.FORMAT_FAILURE, simpleReport.getSubIndication(sigId));
                assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(sigId),
                        i18nProvider.getMessage(MessageTag.BBB_FC_ISVADMDPD_ANS)));
                certificationSigFound = true;

            } else if (Indication.INDETERMINATE.equals(simpleReport.getIndication(sigId))) {
                assertEquals(SubIndication.OUT_OF_BOUNDS_NO_POE, simpleReport.getSubIndication(sigId));
                assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(sigId),
                        i18nProvider.getMessage(MessageTag.BBB_XCV_ICTIVRSC_ANS)));
                assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(sigId),
                        i18nProvider.getMessage(MessageTag.LTV_ISCKNR_ANS1)));
                assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(sigId),
                        i18nProvider.getMessage(MessageTag.ARCH_LTAIVMP_ANS)));
                secondSigFound = true;
            }
        }
        assertTrue(certificationSigFound);
        assertTrue(secondSigFound);
    }

    @Test
    void fieldMDPTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_with_object_modifications.xml"));
        assertNotNull(xmlDiagnosticData);

        XmlSignature xmlSignature = xmlDiagnosticData.getSignatures().get(0);
        XmlPDFSignatureDictionary pdfSignatureDictionary = xmlSignature.getPDFRevision().getPDFSignatureDictionary();

        XmlPDFLockDictionary xmlPDFLockDictionary = new XmlPDFLockDictionary();
        xmlPDFLockDictionary.setAction(PdfLockAction.ALL);
        pdfSignatureDictionary.setFieldMDP(xmlPDFLockDictionary);

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.FAIL);
        validationPolicy.getSignatureConstraints().getBasicSignatureConstraints().setFieldMDP(levelConstraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();
        SimpleReport simpleReport = reports.getSimpleReport();

        boolean certificationSigFound = false;
        boolean secondSigFound = false;
        for (String sigId : simpleReport.getSignatureIdList()) {
            if (Indication.TOTAL_FAILED.equals(simpleReport.getIndication(sigId))) {
                assertEquals(SubIndication.FORMAT_FAILURE, simpleReport.getSubIndication(sigId));
                assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(sigId),
                        i18nProvider.getMessage(MessageTag.BBB_FC_ISVAFMDPD_ANS)));
                certificationSigFound = true;

            } else if (Indication.INDETERMINATE.equals(simpleReport.getIndication(sigId))) {
                assertEquals(SubIndication.OUT_OF_BOUNDS_NO_POE, simpleReport.getSubIndication(sigId));
                assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(sigId),
                        i18nProvider.getMessage(MessageTag.BBB_XCV_ICTIVRSC_ANS)));
                assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(sigId),
                        i18nProvider.getMessage(MessageTag.LTV_ISCKNR_ANS1)));
                assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(sigId),
                        i18nProvider.getMessage(MessageTag.ARCH_LTAIVMP_ANS)));
                secondSigFound = true;
            }
        }
        assertTrue(certificationSigFound);
        assertTrue(secondSigFound);
    }

    @Test
    void sigFieldLockTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_with_object_modifications.xml"));
        assertNotNull(xmlDiagnosticData);

        XmlSignature xmlSignature = xmlDiagnosticData.getSignatures().get(0);

        XmlPDFLockDictionary xmlPDFLockDictionary = new XmlPDFLockDictionary();
        xmlPDFLockDictionary.setAction(PdfLockAction.ALL);
        xmlPDFLockDictionary.setPermissions(CertificationPermission.NO_CHANGE_PERMITTED);
        xmlSignature.getPDFRevision().getFields().get(0).setSigFieldLock(xmlPDFLockDictionary);

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.FAIL);
        validationPolicy.getSignatureConstraints().getBasicSignatureConstraints().setSigFieldLock(levelConstraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();
        SimpleReport simpleReport = reports.getSimpleReport();

        boolean certificationSigFound = false;
        boolean secondSigFound = false;
        for (String sigId : simpleReport.getSignatureIdList()) {
            if (Indication.TOTAL_FAILED.equals(simpleReport.getIndication(sigId))) {
                assertEquals(SubIndication.FORMAT_FAILURE, simpleReport.getSubIndication(sigId));
                assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(sigId),
                        i18nProvider.getMessage(MessageTag.BBB_FC_ISVASFLD_ANS)));
                certificationSigFound = true;

            } else if (Indication.INDETERMINATE.equals(simpleReport.getIndication(sigId))) {
                assertEquals(SubIndication.OUT_OF_BOUNDS_NO_POE, simpleReport.getSubIndication(sigId));
                assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(sigId),
                        i18nProvider.getMessage(MessageTag.BBB_XCV_ICTIVRSC_ANS)));
                assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(sigId),
                        i18nProvider.getMessage(MessageTag.LTV_ISCKNR_ANS1)));
                assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(sigId),
                        i18nProvider.getMessage(MessageTag.ARCH_LTAIVMP_ANS)));
                secondSigFound = true;
            }

        }
        assertTrue(certificationSigFound);
        assertTrue(secondSigFound);
    }

    @Test
    void formFillChangesTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_with_object_modifications.xml"));
        assertNotNull(xmlDiagnosticData);

        XmlSignature xmlSignature = xmlDiagnosticData.getSignatures().get(0);

        XmlObjectModification objectModification = new XmlObjectModification();
        objectModification.setAction(PdfObjectModificationType.CREATION);

        xmlSignature.getPDFRevision().getModificationDetection()
                .getObjectModifications().getSignatureOrFormFill().add(objectModification);

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.FAIL);
        validationPolicy.getSignatureConstraints().getBasicSignatureConstraints().setFormFillChanges(levelConstraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();
        SimpleReport simpleReport = reports.getSimpleReport();

        boolean certificationSigFound = false;
        boolean secondSigFound = false;
        for (String sigId : simpleReport.getSignatureIdList()) {
            if (Indication.TOTAL_FAILED.equals(simpleReport.getIndication(sigId))) {
                assertEquals(SubIndication.FORMAT_FAILURE, simpleReport.getSubIndication(sigId));
                assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(sigId),
                        i18nProvider.getMessage(MessageTag.BBB_FC_DSCNFFSM_ANS)));
                certificationSigFound = true;

            } else if (Indication.INDETERMINATE.equals(simpleReport.getIndication(sigId))) {
                assertEquals(SubIndication.OUT_OF_BOUNDS_NO_POE, simpleReport.getSubIndication(sigId));
                assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(sigId),
                        i18nProvider.getMessage(MessageTag.BBB_XCV_ICTIVRSC_ANS)));
                assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(sigId),
                        i18nProvider.getMessage(MessageTag.LTV_ISCKNR_ANS1)));
                assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(sigId),
                        i18nProvider.getMessage(MessageTag.ARCH_LTAIVMP_ANS)));
                secondSigFound = true;
            }
        }
        assertTrue(certificationSigFound);
        assertTrue(secondSigFound);
    }

    @Test
    void annotationChangesTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_with_object_modifications.xml"));
        assertNotNull(xmlDiagnosticData);

        XmlSignature xmlSignature = xmlDiagnosticData.getSignatures().get(0);

        XmlObjectModification objectModification = new XmlObjectModification();
        objectModification.setAction(PdfObjectModificationType.CREATION);

        xmlSignature.getPDFRevision().getModificationDetection()
                .getObjectModifications().getAnnotationChanges().add(objectModification);

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.FAIL);
        validationPolicy.getSignatureConstraints().getBasicSignatureConstraints().setAnnotationChanges(levelConstraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();
        SimpleReport simpleReport = reports.getSimpleReport();

        boolean certificationSigFound = false;
        boolean secondSigFound = false;
        for (String sigId : simpleReport.getSignatureIdList()) {
            if (Indication.TOTAL_FAILED.equals(simpleReport.getIndication(sigId))) {
                assertEquals(SubIndication.FORMAT_FAILURE, simpleReport.getSubIndication(sigId));
                assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(sigId),
                        i18nProvider.getMessage(MessageTag.BBB_FC_DSCNACMDM_ANS)));
                certificationSigFound = true;

            } else if (Indication.INDETERMINATE.equals(simpleReport.getIndication(sigId))) {
                assertEquals(SubIndication.OUT_OF_BOUNDS_NO_POE, simpleReport.getSubIndication(sigId));
                assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(sigId),
                        i18nProvider.getMessage(MessageTag.BBB_XCV_ICTIVRSC_ANS)));
                assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(sigId),
                        i18nProvider.getMessage(MessageTag.LTV_ISCKNR_ANS1)));
                assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(sigId),
                        i18nProvider.getMessage(MessageTag.ARCH_LTAIVMP_ANS)));
                secondSigFound = true;
            }
        }
        assertTrue(certificationSigFound);
        assertTrue(secondSigFound);
    }

    @Test
    void undefinedChangesTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_with_object_modifications.xml"));
        assertNotNull(xmlDiagnosticData);

        XmlSignature xmlSignature = xmlDiagnosticData.getSignatures().get(0);

        XmlObjectModification undefinedChange = new XmlObjectModification();
        undefinedChange.setAction(PdfObjectModificationType.CREATION);

        xmlSignature.getPDFRevision().getModificationDetection()
                .getObjectModifications().getUndefined().add(undefinedChange);

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.FAIL);
        validationPolicy.getSignatureConstraints().getBasicSignatureConstraints().setUndefinedChanges(levelConstraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();
        SimpleReport simpleReport = reports.getSimpleReport();

        boolean certificationSigFound = false;
        boolean secondSigFound = false;
        for (String sigId : simpleReport.getSignatureIdList()) {
            if (Indication.TOTAL_FAILED.equals(simpleReport.getIndication(sigId))) {
                assertEquals(SubIndication.FORMAT_FAILURE, simpleReport.getSubIndication(sigId));
                assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(sigId),
                        i18nProvider.getMessage(MessageTag.BBB_FC_DSCNUOM_ANS)));
                certificationSigFound = true;

            } else if (Indication.INDETERMINATE.equals(simpleReport.getIndication(sigId))) {
                assertEquals(SubIndication.OUT_OF_BOUNDS_NO_POE, simpleReport.getSubIndication(sigId));
                assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(sigId),
                        i18nProvider.getMessage(MessageTag.BBB_XCV_ICTIVRSC_ANS)));
                assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(sigId),
                        i18nProvider.getMessage(MessageTag.LTV_ISCKNR_ANS1)));
                assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(sigId),
                        i18nProvider.getMessage(MessageTag.ARCH_LTAIVMP_ANS)));
                secondSigFound = true;
            }
        }
        assertTrue(certificationSigFound);
        assertTrue(secondSigFound);
    }

    @Test
    void undefinedChangesTimestampTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_pades_lta_mod_tst.xml"));
        assertNotNull(xmlDiagnosticData);
        ValidationPolicy validationPolicy = loadDefaultPolicy();
        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.FAIL);
        validationPolicy.getTimestampConstraints().getBasicSignatureConstraints().setUndefinedChanges(levelConstraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();
        SimpleReport simpleReport = reports.getSimpleReport();

        List<eu.europa.esig.dss.simplereport.jaxb.XmlTimestamp> signatureTimestamps = simpleReport.getSignatureTimestamps(simpleReport.getFirstSignatureId());
        assertEquals(2, signatureTimestamps.size());

        DetailedReport detailedReport = reports.getDetailedReport();

        boolean sigTstFound = false;
        boolean arcTstFound = false;
        for (eu.europa.esig.dss.simplereport.jaxb.XmlTimestamp timestamp : signatureTimestamps) {
            if (Indication.PASSED.equals(detailedReport.getBasicTimestampValidationIndication(timestamp.getId()))) {
                XmlBasicBuildingBlocks tstBBB = detailedReport.getBasicBuildingBlockById(timestamp.getId());
                assertNotNull(tstBBB);
                assertNull(tstBBB.getFC());
                sigTstFound = true;

            } else if (Indication.FAILED.equals(detailedReport.getBasicTimestampValidationIndication(timestamp.getId()))) {
                assertEquals(SubIndication.FORMAT_FAILURE, detailedReport.getBasicTimestampValidationSubIndication(timestamp.getId()));

                XmlBasicBuildingBlocks tstBBB = detailedReport.getBasicBuildingBlockById(timestamp.getId());
                assertNotNull(tstBBB);

                XmlFC fc = tstBBB.getFC();
                assertNotNull(tstBBB.getFC());
                assertEquals(Indication.FAILED, fc.getConclusion().getIndication());
                assertEquals(SubIndication.FORMAT_FAILURE, fc.getConclusion().getSubIndication());

                boolean undefinedChangedCheckFound = false;
                boolean asicSignedContentCheckFound = false;
                for (XmlConstraint constraint : fc.getConstraint()) {
                    if (MessageTag.BBB_FC_DSCNUOM.getId().equals(constraint.getName().getKey())) {
                        assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
                        assertEquals(MessageTag.BBB_FC_DSCNUOM_ANS.getId(), constraint.getError().getKey());
                        undefinedChangedCheckFound = true;
                    } else if (MessageTag.BBB_FC_ISFP_ASTFORAMC.getId().equals(constraint.getName().getKey())) {
                        asicSignedContentCheckFound = true;
                    } else {
                        assertEquals(XmlStatus.OK, constraint.getStatus());
                    }
                }
                assertTrue(undefinedChangedCheckFound);
                assertFalse(asicSignedContentCheckFound);
                arcTstFound = true;

            }
        }
        assertTrue(sigTstFound);
        assertTrue(arcTstFound);
    }

    @Test
    void noUndefinedChangesTimestampTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_pades_lta_mod_tst.xml"));
        assertNotNull(xmlDiagnosticData);

        XmlTimestamp xmlTimestamp = xmlDiagnosticData.getUsedTimestamps().get(1);

        xmlTimestamp.getPDFRevision().getModificationDetection().setObjectModifications(new XmlObjectModifications());

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.FAIL);
        validationPolicy.getTimestampConstraints().getBasicSignatureConstraints().setUndefinedChanges(levelConstraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();
        SimpleReport simpleReport = reports.getSimpleReport();

        List<eu.europa.esig.dss.simplereport.jaxb.XmlTimestamp> signatureTimestamps = simpleReport.getSignatureTimestamps(simpleReport.getFirstSignatureId());
        assertEquals(2, signatureTimestamps.size());

        DetailedReport detailedReport = reports.getDetailedReport();

        boolean sigTstFound = false;
        boolean arcTstFound = false;
        for (eu.europa.esig.dss.simplereport.jaxb.XmlTimestamp timestamp : signatureTimestamps) {
            assertEquals(Indication.PASSED, detailedReport.getBasicTimestampValidationIndication(timestamp.getId()));

            XmlBasicBuildingBlocks tstBBB = detailedReport.getBasicBuildingBlockById(timestamp.getId());
            if (tstBBB.getFC() == null) {
                sigTstFound = true;

            } else {
                XmlFC fc = tstBBB.getFC();
                assertNotNull(tstBBB.getFC());
                assertEquals(Indication.PASSED, fc.getConclusion().getIndication());

                boolean undefinedChangedCheckFound = false;
                boolean asicSignedContentCheckFound = false;
                for (XmlConstraint constraint : fc.getConstraint()) {
                    assertEquals(XmlStatus.OK, constraint.getStatus());
                    if (MessageTag.BBB_FC_DSCNUOM.getId().equals(constraint.getName().getKey())) {
                        undefinedChangedCheckFound = true;
                    } else if (MessageTag.BBB_FC_ISFP_ASTFORAMC.getId().equals(constraint.getName().getKey())) {
                        asicSignedContentCheckFound = true;
                    }
                }
                assertTrue(undefinedChangedCheckFound);
                assertFalse(asicSignedContentCheckFound);
                arcTstFound = true;

            }
        }
        assertTrue(sigTstFound);
        assertTrue(arcTstFound);
    }

    @Test
    void invalidByteRangeTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_pkcs7.xml"));
        assertNotNull(xmlDiagnosticData);

        List<eu.europa.esig.dss.diagnostic.jaxb.XmlSignature> xmlSignatures = xmlDiagnosticData.getSignatures();
        assertEquals(1, xmlSignatures.size());

        eu.europa.esig.dss.diagnostic.jaxb.XmlSignature xmlSignature = xmlSignatures.get(0);
        xmlSignature.getBasicSignature().setSignatureIntact(false);
        xmlSignature.getBasicSignature().setSignatureValid(false);

        XmlPDFSignatureDictionary pdfSignatureDictionary = xmlSignature.getPDFRevision().getPDFSignatureDictionary();
        pdfSignatureDictionary.setConsistent(false);

        XmlByteRange signatureByteRange = pdfSignatureDictionary.getSignatureByteRange();
        signatureByteRange.setValid(false);

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.FAIL);
        validationPolicy.getSignatureConstraints().getBasicSignatureConstraints().setByteRange(levelConstraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();
        assertNotNull(reports);

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_FAILED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.FORMAT_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_FC_IBRV_ANS)));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_CV_ISI_ANS)));

        DetailedReport detailedReport = reports.getDetailedReport();
        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertNotNull(signatureBBB);

        XmlFC xmlFC = signatureBBB.getFC();
        assertNotNull(xmlFC);

        boolean byteRangeCheckFound = false;
        for (XmlConstraint constraint : xmlFC.getConstraint()) {
            if (MessageTag.BBB_FC_IBRV.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
                assertEquals(MessageTag.BBB_FC_IBRV_ANS.getId(), constraint.getError().getKey());
                byteRangeCheckFound = true;
            } else {
                assertEquals(XmlStatus.OK, constraint.getStatus());
            }
        }
        assertTrue(byteRangeCheckFound);

        checkReports(reports);
    }

    @Test
    void invalidByteRangeWarnTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_pkcs7.xml"));
        assertNotNull(xmlDiagnosticData);

        List<eu.europa.esig.dss.diagnostic.jaxb.XmlSignature> xmlSignatures = xmlDiagnosticData.getSignatures();
        assertEquals(1, xmlSignatures.size());

        eu.europa.esig.dss.diagnostic.jaxb.XmlSignature xmlSignature = xmlSignatures.get(0);
        xmlSignature.getBasicSignature().setSignatureIntact(false);
        xmlSignature.getBasicSignature().setSignatureValid(false);

        XmlByteRange signatureByteRange = xmlSignature.getPDFRevision().getPDFSignatureDictionary().getSignatureByteRange();
        signatureByteRange.setValid(false);

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.WARN);
        validationPolicy.getSignatureConstraints().getBasicSignatureConstraints().setByteRange(levelConstraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();
        assertNotNull(reports);

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_FAILED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.SIG_CRYPTO_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
        assertFalse(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_FC_IBRV_ANS)));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_CV_ISI_ANS)));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationWarnings(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_FC_IBRV_ANS)));

        DetailedReport detailedReport = reports.getDetailedReport();
        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertNotNull(signatureBBB);

        XmlFC xmlFC = signatureBBB.getFC();
        assertNotNull(xmlFC);

        boolean byteRangeCheckFound = false;
        for (XmlConstraint constraint : xmlFC.getConstraint()) {
            if (MessageTag.BBB_FC_IBRV.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.WARNING, constraint.getStatus());
                assertEquals(MessageTag.BBB_FC_IBRV_ANS.getId(), constraint.getWarning().getKey());
                byteRangeCheckFound = true;
            } else {
                assertEquals(XmlStatus.OK, constraint.getStatus());
            }
        }
        assertTrue(byteRangeCheckFound);

        checkReports(reports);
    }

    @Test
    void byteRangeCollisionTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_pades_lta_mod_tst.xml"));
        assertNotNull(xmlDiagnosticData);

        XmlTimestamp xmlTimestamp = xmlDiagnosticData.getUsedTimestamps().get(1);
        XmlByteRange byteRange = xmlTimestamp.getPDFRevision().getPDFSignatureDictionary().getSignatureByteRange();
        byteRange.getValue().clear();
        byteRange.getValue().addAll(Arrays.asList(BigInteger.valueOf(0), BigInteger.valueOf(156500), BigInteger.valueOf(176500), BigInteger.valueOf(500)));

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.FAIL);
        validationPolicy.getSignatureConstraints().getBasicSignatureConstraints().setByteRangeCollision(levelConstraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_FAILED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.FORMAT_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_FC_DBTOOST_ANS)));

        DetailedReport detailedReport = reports.getDetailedReport();
        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertEquals(Indication.FAILED, signatureBBB.getConclusion().getIndication());
        assertEquals(SubIndication.FORMAT_FAILURE, signatureBBB.getConclusion().getSubIndication());

        XmlFC fc = signatureBBB.getFC();
        assertEquals(Indication.FAILED, fc.getConclusion().getIndication());
        assertEquals(SubIndication.FORMAT_FAILURE, fc.getConclusion().getSubIndication());

        boolean byteRangeCollisionCheckFound = false;
        for (XmlConstraint constraint : fc.getConstraint()) {
            if (MessageTag.BBB_FC_DBTOOST.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
                assertEquals(MessageTag.BBB_FC_DBTOOST_ANS.getId(), constraint.getError().getKey());
                byteRangeCollisionCheckFound = true;
            } else {
                assertEquals(XmlStatus.OK, constraint.getStatus());
            }
        }
        assertTrue(byteRangeCollisionCheckFound);
    }

    @Test
    void byteRangeAllDocumentTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_pades_lta_mod_tst.xml"));
        assertNotNull(xmlDiagnosticData);

        XmlTimestamp xmlTimestamp = xmlDiagnosticData.getUsedTimestamps().get(1);
        XmlByteRange byteRange = xmlTimestamp.getPDFRevision().getPDFSignatureDictionary().getSignatureByteRange();
        byteRange.setValid(false);

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.FAIL);
        validationPolicy.getSignatureConstraints().getBasicSignatureConstraints().setByteRangeAllDocument(levelConstraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_FAILED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.FORMAT_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_FC_DASTHVBR_ANS)));

        DetailedReport detailedReport = reports.getDetailedReport();
        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertEquals(Indication.FAILED, signatureBBB.getConclusion().getIndication());
        assertEquals(SubIndication.FORMAT_FAILURE, signatureBBB.getConclusion().getSubIndication());

        XmlFC fc = signatureBBB.getFC();
        assertEquals(Indication.FAILED, fc.getConclusion().getIndication());
        assertEquals(SubIndication.FORMAT_FAILURE, fc.getConclusion().getSubIndication());

        boolean byteRangeAllDocumentCheckFound = false;
        for (XmlConstraint constraint : fc.getConstraint()) {
            if (MessageTag.BBB_FC_DASTHVBR.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
                assertEquals(MessageTag.BBB_FC_DASTHVBR_ANS.getId(), constraint.getError().getKey());
                byteRangeAllDocumentCheckFound = true;
            } else {
                assertEquals(XmlStatus.OK, constraint.getStatus());
            }
        }
        assertTrue(byteRangeAllDocumentCheckFound);
    }

    @Test
    void pdfSignatureDictionaryInvalidTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_pdfa.xml"));
        assertNotNull(xmlDiagnosticData);

        XmlSignature xmlSignature = xmlDiagnosticData.getSignatures().get(0);
        xmlSignature.getPDFRevision().getPDFSignatureDictionary().setConsistent(false);

        ValidationPolicy validationPolicy = loadDefaultPolicy();

        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.FAIL);
        validationPolicy.getSignatureConstraints().getBasicSignatureConstraints().setPdfSignatureDictionary(levelConstraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();
        assertNotNull(reports);

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_FAILED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.FORMAT_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_FC_ISDC_ANS)));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.FAILED, detailedReport.getBasicValidationIndication(detailedReport.getFirstSignatureId()));
        assertEquals(SubIndication.FORMAT_FAILURE, detailedReport.getBasicValidationSubIndication(detailedReport.getFirstSignatureId()));

        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertNotNull(signatureBBB);
        assertEquals(Indication.FAILED, signatureBBB.getConclusion().getIndication());
        assertEquals(SubIndication.FORMAT_FAILURE, signatureBBB.getConclusion().getSubIndication());

        XmlFC fc = signatureBBB.getFC();
        assertEquals(Indication.FAILED, fc.getConclusion().getIndication());
        assertEquals(SubIndication.FORMAT_FAILURE, fc.getConclusion().getSubIndication());

        boolean signDictCheckFound = false;
        for (XmlConstraint constraint : fc.getConstraint()) {
            if (MessageTag.BBB_FC_ISDC.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
                assertEquals(MessageTag.BBB_FC_ISDC_ANS.getId(), constraint.getError().getKey());
                signDictCheckFound = true;
            }
        }
        assertTrue(signDictCheckFound);
    }

}
