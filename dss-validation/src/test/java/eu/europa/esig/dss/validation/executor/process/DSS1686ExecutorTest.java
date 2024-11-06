package eu.europa.esig.dss.validation.executor.process;

import eu.europa.esig.dss.detailedreport.DetailedReport;
import eu.europa.esig.dss.detailedreport.jaxb.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessArchivalData;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessArchivalDataTimestamp;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessBasicSignature;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessBasicTimestamp;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessLongTermData;
import eu.europa.esig.dss.diagnostic.DiagnosticDataFacade;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SignatureQualification;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.jaxb.object.Message;
import eu.europa.esig.dss.policy.ValidationPolicy;
import eu.europa.esig.dss.policy.jaxb.BasicSignatureConstraints;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.policy.jaxb.SignatureConstraints;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.executor.signature.DefaultSignatureProcessExecutor;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.validationreport.jaxb.SignatureValidationReportType;
import eu.europa.esig.validationreport.jaxb.ValidationReportType;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DSS1686ExecutorTest extends AbstractProcessExecutorTest {

    @Test
    void testDSS1686() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/diag-data/DSS-1686/dss-1686.xml"));
        assertNotNull(diagnosticData);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();
//		reports.print();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SignatureQualification.INDETERMINATE_QESIG, simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()));

        ValidationReportType etsiValidationReport = reports.getEtsiValidationReportJaxb();
        assertNotNull(etsiValidationReport);
        SignatureValidationReportType signatureValidationReport = etsiValidationReport.getSignatureValidationReport().get(0);
        assertNotNull(signatureValidationReport);
        assertEquals(simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()),
                SignatureQualification.forURI(signatureValidationReport.getSignatureQuality().getSignatureQualityInformation().get(0)));

        DetailedReport detailedReport = reports.getDetailedReport();
        eu.europa.esig.dss.detailedreport.jaxb.XmlSignature xmlSignature = detailedReport.getSignatures().get(0);

        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(xmlSignature.getId());

        XmlValidationProcessBasicSignature validationProcessBasicSignature = xmlSignature.getValidationProcessBasicSignature();
        XmlValidationProcessArchivalData validationProcessArchivalData = xmlSignature.getValidationProcessArchivalData();

        assertEquals(signatureBBB.getConclusion().getIndication(),
                validationProcessArchivalData.getConclusion().getIndication());
        assertEquals(signatureBBB.getConclusion().getSubIndication(),
                validationProcessArchivalData.getConclusion().getSubIndication());
        assertTrue(signatureBBB.getConclusion().getErrors().containsAll(
                validationProcessBasicSignature.getConclusion().getErrors()));
        assertTrue(signatureBBB.getConclusion().getWarnings().containsAll(
                validationProcessBasicSignature.getConclusion().getWarnings()));

        assertNotNull(signatureBBB.getPSV());
        assertTrue(signatureBBB.getConclusion().getErrors().containsAll(
                signatureBBB.getPSV().getConclusion().getErrors()));
        assertTrue(signatureBBB.getConclusion().getWarnings().containsAll(
                signatureBBB.getPSV().getConclusion().getWarnings()));

        List<XmlConstraint> constraints = validationProcessArchivalData.getConstraint();
        List<String> timestampIds = detailedReport.getTimestampIds();

        int validationTSTCounter = 0;
        for (String timestampId : timestampIds) {
            for (XmlConstraint constraint : constraints) {
                if (Utils.isStringNotEmpty(constraint.getId()) && constraint.getId().contains(timestampId)) {
                    if (MessageTag.ADEST_IBSVPTADC.getId().equals(constraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, constraint.getStatus());
                        ++validationTSTCounter;
                    }
                }
            }
            assertEquals(Indication.PASSED, detailedReport.getBasicBuildingBlocksIndication(timestampId));
            assertNull(detailedReport.getBasicBuildingBlocksSubIndication(timestampId));
        }
        assertEquals(3, validationTSTCounter);

        assertEquals(3, xmlSignature.getTimestamps().size());

        int basicTstSuccessCounter = 0;
        int basicTstFailureCounter = 0;
        for (eu.europa.esig.dss.detailedreport.jaxb.XmlTimestamp xmlTimestamp : xmlSignature.getTimestamps()) {
            boolean passedTst = false;
            XmlValidationProcessBasicTimestamp timestampBasicValidation = xmlTimestamp.getValidationProcessBasicTimestamp();
            if (Indication.PASSED.equals(timestampBasicValidation.getConclusion().getIndication())) {
                passedTst = true;
                ++basicTstSuccessCounter;
            } else {
                assertEquals(Indication.INDETERMINATE, timestampBasicValidation.getConclusion().getIndication());
                assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, timestampBasicValidation.getConclusion().getSubIndication());
                ++basicTstFailureCounter;
            }

            boolean basicTstAcceptableCheckFound = false;
            boolean basicTstConclusiveCheckFound = false;
            boolean pastTstAcceptableCheckFound = false;
            boolean digestAlgoTstCheckFound = false;
            boolean messageImprintTstCheckFound = false;

            XmlValidationProcessArchivalDataTimestamp timestampArchivalDataValidation = xmlTimestamp.getValidationProcessArchivalDataTimestamp();
            assertEquals(Indication.PASSED, timestampArchivalDataValidation.getConclusion().getIndication());
            for (XmlConstraint constraint : timestampArchivalDataValidation.getConstraint()) {
                if (MessageTag.ARCH_IRTVBBA.getId().equals(constraint.getName().getKey())) {
                    assertEquals(XmlStatus.OK, constraint.getStatus());
                    basicTstAcceptableCheckFound = true;

                } else if (MessageTag.ADEST_IBSVPTC.getId().equals(constraint.getName().getKey())) {
                    if (passedTst) {
                        assertEquals(XmlStatus.OK, constraint.getStatus());
                    } else {
                        assertEquals(XmlStatus.WARNING, constraint.getStatus());
                        assertEquals(MessageTag.ADEST_IBSVPTC_ANS.getId(), constraint.getWarning().getKey());
                    }
                    basicTstConclusiveCheckFound = true;

                } else if (MessageTag.PSV_IPTVC.getId().equals(constraint.getName().getKey())) {
                    assertEquals(XmlStatus.OK, constraint.getStatus());
                    pastTstAcceptableCheckFound = true;

                } else if (MessageTag.ARCH_ICHFCRLPOET.getId().equals(constraint.getName().getKey())) {
                    assertEquals(XmlStatus.OK, constraint.getStatus());
                    digestAlgoTstCheckFound = true;

                } else if (MessageTag.BBB_SAV_DMICTSTMCMI.getId().equals(constraint.getName().getKey())) {
                    assertEquals(XmlStatus.OK, constraint.getStatus());
                    messageImprintTstCheckFound = true;

                } else {
                    assertEquals(XmlStatus.OK, constraint.getStatus());
                }
            }

            assertTrue(basicTstAcceptableCheckFound);
            assertTrue(basicTstConclusiveCheckFound);
            if (!passedTst) {
                assertTrue(pastTstAcceptableCheckFound);
            }
            assertTrue(digestAlgoTstCheckFound);
            assertTrue(messageImprintTstCheckFound);
        }
        assertEquals(1, basicTstSuccessCounter);
        assertEquals(2, basicTstFailureCounter);

        validateBestSigningTimes(reports);
        checkReports(reports);
    }

    @Test
    void testDSS1686CheckManifestEntryExistence() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/diag-data/DSS-1686/dss-1686.xml"));
        assertNotNull(diagnosticData);

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        SignatureConstraints signatureConstraints = validationPolicy.getSignatureConstraints();
        BasicSignatureConstraints basicSignatureConstraints = signatureConstraints.getBasicSignatureConstraints();

        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.FAIL);
        basicSignatureConstraints.setManifestEntryObjectExistence(levelConstraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();
        // reports.print();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.SIGNED_DATA_NOT_FOUND, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SignatureQualification.INDETERMINATE_ADESIG, simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()));

        List<Message> errors = simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId());
        assertTrue(checkMessageValuePresence(errors, i18nProvider.getMessage(MessageTag.BBB_CV_ISMEC_ANS)));

        validateBestSigningTimes(reports);
        checkReports(reports);
    }

    @Test
    void testDSS1686CryptoWarn() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/diag-data/DSS-1686/dss-1686.xml"));
        assertNotNull(diagnosticData);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadPolicyCryptoWarn());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();
        // reports.print();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SignatureQualification.QESIG, simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()));

        ValidationReportType etsiValidationReport = reports.getEtsiValidationReportJaxb();
        assertNotNull(etsiValidationReport);
        SignatureValidationReportType signatureValidationReport = etsiValidationReport.getSignatureValidationReport().get(0);
        assertNotNull(signatureValidationReport);
        assertEquals(simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()),
                SignatureQualification.forURI(signatureValidationReport.getSignatureQuality().getSignatureQualityInformation().get(0)));

        Date timestampProductionDate = diagnosticData.getSignatures().get(0).getFoundTimestamps().get(0).getTimestamp().getProductionTime();
        Date bestSignatureTime = simpleReport.getBestSignatureTime(simpleReport.getFirstSignatureId());
        assertEquals(timestampProductionDate, bestSignatureTime);

        assertEquals(0, simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()).size());
        assertEquals(4, simpleReport.getAdESValidationWarnings(simpleReport.getFirstSignatureId()).size());

        validateBestSigningTimes(reports);
        checkReports(reports);
    }

    @Test
    void testDSS1686BrokenSigTimestamp() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade()
                .unmarshall(new File("src/test/resources/diag-data/DSS-1686/dss-1686-broken-signature-timestamp.xml"));
        assertNotNull(diagnosticData);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
        // Sig TST is broken -> best signing time is not updated
        assertEquals(SignatureQualification.INDETERMINATE_QESIG, simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()));

        DetailedReport detailedReport = reports.getDetailedReport();
        eu.europa.esig.dss.detailedreport.jaxb.XmlSignature xmlSignature = detailedReport.getSignatures().get(0);
        XmlValidationProcessBasicTimestamp validationProcessTimestamp = xmlSignature.getTimestamps().get(0).getValidationProcessBasicTimestamp();
        assertEquals(Indication.FAILED, validationProcessTimestamp.getConclusion().getIndication());
        assertEquals(SubIndication.HASH_FAILURE, validationProcessTimestamp.getConclusion().getSubIndication());

        XmlValidationProcessLongTermData validationProcessLongTermData = xmlSignature.getValidationProcessLongTermData();
        boolean sigTstMessageImprintCheckFound = false;
        for (XmlConstraint constraint : validationProcessLongTermData.getConstraint()) {
            if (MessageTag.BBB_SAV_DMICTSTMCMI.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.WARNING, constraint.getStatus());
                assertEquals(MessageTag.BBB_SAV_DMICTSTMCMI_ANS.getId(), constraint.getWarning().getKey());
                sigTstMessageImprintCheckFound = true;
            }
        }
        assertTrue(sigTstMessageImprintCheckFound);

        validateBestSigningTimes(reports);
        checkReports(reports);
    }

    @Test
    void testDSS1686BrokenSigTimestampSkipDigestMatcherCheck() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade()
                .unmarshall(new File("src/test/resources/diag-data/DSS-1686/dss-1686-broken-signature-timestamp.xml"));
        assertNotNull(diagnosticData);

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        BasicSignatureConstraints timestampBasicSignatureConstraints = validationPolicy.getTimestampConstraints()
                .getBasicSignatureConstraints();

        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.WARN);

        timestampBasicSignatureConstraints.setReferenceDataExistence(levelConstraint);
        timestampBasicSignatureConstraints.setReferenceDataIntact(levelConstraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SignatureQualification.INDETERMINATE_QESIG, simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()));

        DetailedReport detailedReport = reports.getDetailedReport();
        eu.europa.esig.dss.detailedreport.jaxb.XmlSignature xmlSignature = detailedReport.getSignatures().get(0);
        XmlValidationProcessBasicTimestamp validationProcessTimestamp = xmlSignature.getTimestamps().get(0).getValidationProcessBasicTimestamp();
        assertEquals(Indication.INDETERMINATE, validationProcessTimestamp.getConclusion().getIndication());
        assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, validationProcessTimestamp.getConclusion().getSubIndication());

        XmlValidationProcessLongTermData validationProcessLongTermData = xmlSignature.getValidationProcessLongTermData();
        boolean sigTstMessageImprintCheckFound = false;
        for (XmlConstraint constraint : validationProcessLongTermData.getConstraint()) {
            if (MessageTag.BBB_SAV_DMICTSTMCMI.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.WARNING, constraint.getStatus());
                assertEquals(MessageTag.BBB_SAV_DMICTSTMCMI_ANS.getId(), constraint.getWarning().getKey());
                sigTstMessageImprintCheckFound = true;
            }
        }
        assertTrue(sigTstMessageImprintCheckFound);

        validateBestSigningTimes(reports);
        checkReports(reports);
    }

    @Test
    void testDSS1686BrokenSigTimestampCryptoWarn() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade()
                .unmarshall(new File("src/test/resources/diag-data/DSS-1686/dss-1686-broken-signature-timestamp.xml"));
        assertNotNull(diagnosticData);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadPolicyCryptoWarn());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        DetailedReport detailedReport = reports.getDetailedReport();
        XmlBasicBuildingBlocks basicBuildingBlockSigTimestamp = detailedReport
                .getBasicBuildingBlockById("T-BFE8B3E24DC946E83C989B65401FE6B41A8EC7A3C047F7579E01F5EA39D718B1");
        assertNotNull(basicBuildingBlockSigTimestamp);
        assertEquals(Indication.FAILED, basicBuildingBlockSigTimestamp.getConclusion().getIndication());
        assertEquals(SubIndication.HASH_FAILURE, basicBuildingBlockSigTimestamp.getConclusion().getSubIndication());

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        // Sig TST is broken -> best signing time is not updated
        assertEquals(SignatureQualification.QESIG, simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()));

        validateBestSigningTimes(reports);
        checkReports(reports);
    }

    @Test
    void testDSS1686BrokenSigAndArchivalTimestamp() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade()
                .unmarshall(new File("src/test/resources/diag-data/DSS-1686/dss-1686-broken-signature-and-archival-timestamp.xml"));
        assertNotNull(diagnosticData);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        // Sig TST + archival TST are broken -> unable to process the past signature
        // validation + POE extraction
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SignatureQualification.INDETERMINATE_ADESIG, simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()));

        DetailedReport detailedReport = reports.getDetailedReport();
        eu.europa.esig.dss.detailedreport.jaxb.XmlSignature xmlSignature = detailedReport.getSignatures().get(0);

        int validationTSTPassedCounter = 0;
        int validationTSTFailedCounter = 0;
        XmlValidationProcessArchivalData validationProcessArchivalData = xmlSignature.getValidationProcessArchivalData();
        List<XmlConstraint> constraints = validationProcessArchivalData.getConstraint();
        List<String> timestampIds = detailedReport.getTimestampIds();
        for (String timestampId : timestampIds) {
            for (XmlConstraint constraint : constraints) {
                if (timestampId.equals(constraint.getId())) {
                    if (MessageTag.ADEST_IBSVPTADC.getId().equals(constraint.getName().getKey())) {
                        if (XmlStatus.OK.equals(constraint.getStatus())) {
                            assertEquals(Indication.PASSED, detailedReport.getBasicBuildingBlocksIndication(timestampId));
                            ++validationTSTPassedCounter;
                        } else if (XmlStatus.WARNING.equals(constraint.getStatus())) {
                            assertEquals(Indication.FAILED, detailedReport.getBasicBuildingBlocksIndication(timestampId));
                            assertEquals(SubIndication.HASH_FAILURE, detailedReport.getBasicBuildingBlocksSubIndication(timestampId));
                            ++validationTSTFailedCounter;
                        }
                    }
                }
            }
        }
        assertEquals(1, validationTSTPassedCounter);
        assertEquals(2, validationTSTFailedCounter);

        int basicTstSuccessCounter = 0;
        int basicTstFailureCounter = 0;

        for (eu.europa.esig.dss.detailedreport.jaxb.XmlTimestamp xmlTimestamp : xmlSignature.getTimestamps()) {
            boolean passedTst = false;
            XmlValidationProcessBasicTimestamp timestampBasicValidation = xmlTimestamp.getValidationProcessBasicTimestamp();
            if (Indication.PASSED.equals(timestampBasicValidation.getConclusion().getIndication())) {
                passedTst = true;
                ++basicTstSuccessCounter;
            } else {
                ++basicTstFailureCounter;
            }

            boolean basicTstAcceptableCheckFound = false;
            boolean basicTstConclusiveCheckFound = false;
            boolean pastTstAcceptableCheckFound = false;
            boolean digestAlgoTstCheckFound = false;
            boolean messageImprintTstCheckFound = false;

            XmlValidationProcessArchivalDataTimestamp timestampArchivalDataValidation = xmlTimestamp.getValidationProcessArchivalDataTimestamp();
            for (XmlConstraint constraint : timestampArchivalDataValidation.getConstraint()) {
                if (MessageTag.ARCH_IRTVBBA.getId().equals(constraint.getName().getKey())) {
                    if (XmlStatus.OK.equals(constraint.getStatus())) {
                        assertTrue(passedTst);
                        assertEquals(Indication.PASSED, timestampArchivalDataValidation.getConclusion().getIndication());
                    } else {
                        assertEquals(Indication.FAILED, timestampArchivalDataValidation.getConclusion().getIndication());
                        assertEquals(SubIndication.HASH_FAILURE, timestampArchivalDataValidation.getConclusion().getSubIndication());
                    }
                    basicTstAcceptableCheckFound = true;

                } else if (MessageTag.ADEST_IBSVPTC.getId().equals(constraint.getName().getKey())) {
                    assertTrue(passedTst);
                    assertEquals(XmlStatus.OK, constraint.getStatus());
                    basicTstConclusiveCheckFound = true;

                } else if (MessageTag.PSV_IPTVC.getId().equals(constraint.getName().getKey())) {
                    assertTrue(passedTst);
                    assertEquals(XmlStatus.OK, constraint.getStatus());
                    pastTstAcceptableCheckFound = true;

                } else if (MessageTag.ARCH_ICHFCRLPOET.getId().equals(constraint.getName().getKey())) {
                    assertTrue(passedTst);
                    assertEquals(XmlStatus.OK, constraint.getStatus());
                    digestAlgoTstCheckFound = true;

                } else if (MessageTag.BBB_SAV_DMICTSTMCMI.getId().equals(constraint.getName().getKey())) {
                    assertEquals(XmlStatus.OK, constraint.getStatus());
                    assertTrue(passedTst);
                    messageImprintTstCheckFound = true;

                } else {
                    assertEquals(XmlStatus.OK, constraint.getStatus());
                }
            }

            assertTrue(basicTstAcceptableCheckFound);
            if (passedTst) {
                assertTrue(basicTstConclusiveCheckFound);
                assertFalse(pastTstAcceptableCheckFound);
                assertTrue(digestAlgoTstCheckFound);
                assertTrue(messageImprintTstCheckFound);
            }
        }

        assertEquals(1, basicTstSuccessCounter);
        assertEquals(2, basicTstFailureCounter);

        validateBestSigningTimes(reports);
        checkReports(reports);
    }

    @Test
    void testDSS1686BrokenSigAndArchivalTimestampSkipDigestMatcherCheck() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/DSS-1686/dss-1686-broken-signature-and-archival-timestamp.xml"));
        assertNotNull(diagnosticData);

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        BasicSignatureConstraints timestampBasicConstraints = validationPolicy.getTimestampConstraints().getBasicSignatureConstraints();

        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.WARN);

        timestampBasicConstraints.setReferenceDataExistence(levelConstraint);
        timestampBasicConstraints.setReferenceDataIntact(levelConstraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        // Sig TST + archival TST are broken -> unable to process the past signature
        // validation + POE extraction
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SignatureQualification.INDETERMINATE_ADESIG, simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()));

        int tstPassedCounter = 0;

        DetailedReport detailedReport = reports.getDetailedReport();
        eu.europa.esig.dss.detailedreport.jaxb.XmlSignature xmlSignature = detailedReport.getSignatures().get(0);
        XmlValidationProcessArchivalData validationProcessArchivalData = xmlSignature.getValidationProcessArchivalData();
        List<XmlConstraint> constraints = validationProcessArchivalData.getConstraint();
        List<String> timestampIds = detailedReport.getTimestampIds();
        for (String timestampId : timestampIds) {
            for (XmlConstraint constraint : constraints) {
                if (timestampId.equals(constraint.getId())) {
                    if (MessageTag.ADEST_IBSVPTADC.getId().equals(constraint.getName().getKey())) {
                        if (XmlStatus.OK.equals(constraint.getStatus())) {
                            ++tstPassedCounter;
                        }
                    }
                }
            }
            assertEquals(Indication.PASSED, detailedReport.getBasicBuildingBlocksIndication(timestampId));
        }
        assertEquals(3, tstPassedCounter);

        int basicTstSuccessCounter = 0;
        int basicTstFailureCounter = 0;

        int messageImprintCheckPassedCounter = 0;
        int messageImprintCheckFailedCounter = 0;

        for (eu.europa.esig.dss.detailedreport.jaxb.XmlTimestamp xmlTimestamp : xmlSignature.getTimestamps()) {
            boolean passedTst = false;
            XmlValidationProcessBasicTimestamp timestampBasicValidation = xmlTimestamp.getValidationProcessBasicTimestamp();
            if (Indication.PASSED.equals(timestampBasicValidation.getConclusion().getIndication())) {
                passedTst = true;
                ++basicTstSuccessCounter;
            } else {
                assertEquals(Indication.INDETERMINATE, timestampBasicValidation.getConclusion().getIndication());
                assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, timestampBasicValidation.getConclusion().getSubIndication());
                ++basicTstFailureCounter;
            }

            boolean basicTstAcceptableCheckFound = false;
            boolean basicTstConclusiveCheckFound = false;
            boolean pastTstAcceptableCheckFound = false;
            boolean digestAlgoTstCheckFound = false;
            boolean messageImprintTstCheckFound = false;

            XmlValidationProcessArchivalDataTimestamp timestampArchivalDataValidation = xmlTimestamp.getValidationProcessArchivalDataTimestamp();
            assertEquals(Indication.PASSED, timestampArchivalDataValidation.getConclusion().getIndication());
            for (XmlConstraint constraint : timestampArchivalDataValidation.getConstraint()) {
                if (MessageTag.ARCH_IRTVBBA.getId().equals(constraint.getName().getKey())) {
                    assertEquals(XmlStatus.OK, constraint.getStatus());
                    basicTstAcceptableCheckFound = true;

                } else if (MessageTag.ADEST_IBSVPTC.getId().equals(constraint.getName().getKey())) {
                    if (passedTst) {
                        assertEquals(XmlStatus.OK, constraint.getStatus());
                    } else {
                        assertEquals(XmlStatus.WARNING, constraint.getStatus());
                        assertEquals(MessageTag.ADEST_IBSVPTC_ANS.getId(), constraint.getWarning().getKey());
                    }
                    basicTstConclusiveCheckFound = true;

                } else if (MessageTag.PSV_IPTVC.getId().equals(constraint.getName().getKey())) {
                    assertEquals(XmlStatus.OK, constraint.getStatus());
                    pastTstAcceptableCheckFound = true;

                } else if (MessageTag.ARCH_ICHFCRLPOET.getId().equals(constraint.getName().getKey())) {
                    assertEquals(XmlStatus.OK, constraint.getStatus());
                    digestAlgoTstCheckFound = true;

                } else if (MessageTag.BBB_SAV_DMICTSTMCMI.getId().equals(constraint.getName().getKey())) {
                    if (XmlStatus.OK.equals(constraint.getStatus())) {
                        ++messageImprintCheckPassedCounter;
                    } else {
                        ++messageImprintCheckFailedCounter;
                    }
                    messageImprintTstCheckFound = true;

                } else {
                    assertEquals(XmlStatus.OK, constraint.getStatus());
                }
            }

            assertTrue(basicTstAcceptableCheckFound);
            assertTrue(basicTstConclusiveCheckFound);
            if (!passedTst) {
                assertTrue(pastTstAcceptableCheckFound);
            }
            assertTrue(digestAlgoTstCheckFound);
            assertTrue(messageImprintTstCheckFound);
        }

        assertEquals(1, basicTstSuccessCounter);
        assertEquals(2, basicTstFailureCounter);
        assertEquals(1, messageImprintCheckPassedCounter);
        assertEquals(2, messageImprintCheckFailedCounter);

        validateBestSigningTimes(reports);
        checkReports(reports);
    }

    @Test
    void testDSS1686noSignedDataFound() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade()
                .unmarshall(new File("src/test/resources/diag-data/DSS-1686/dss-1686-signedData-notFound.xml"));
        assertNotNull(diagnosticData);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.SIGNED_DATA_NOT_FOUND, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SignatureQualification.INDETERMINATE_ADESIG, simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()));

        Date timestampProductionDate = diagnosticData.getSignatures().get(0).getFoundTimestamps().get(0).getTimestamp().getProductionTime();
        Date bestSignatureTime = simpleReport.getBestSignatureTime(simpleReport.getFirstSignatureId());
        assertNotEquals(timestampProductionDate, bestSignatureTime);
        assertEquals(diagnosticData.getValidationDate(), bestSignatureTime);

        List<Message> errors = simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId());
        assertEquals(4, errors.size());

        assertTrue(checkMessageValuePresence(errors,
                i18nProvider.getMessage(MessageTag.ASCCM_AR_ANS_ANR, DigestAlgorithm.SHA1, MessageTag.ACCM_POS_SIG_SIG)));
        assertTrue(checkMessageValuePresence(errors,
                i18nProvider.getMessage(MessageTag.ASCCM_AR_ANS_ANR, DigestAlgorithm.SHA1, MessageTag.ACCM_POS_REVOC_SIG)));
        assertTrue(checkMessageValuePresence(errors, i18nProvider.getMessage(MessageTag.BBB_CV_IRDOF_ANS)));
        assertTrue(checkMessageValuePresence(errors, i18nProvider.getMessage(MessageTag.BBB_XCV_SUB_ANS)));

        validateBestSigningTimes(reports);
        checkReports(reports);
    }

    @Test
    void testDSS1686noPOE() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade()
                .unmarshall(new File("src/test/resources/diag-data/DSS-1686/dss-1686-noPOE.xml"));
        assertNotNull(diagnosticData);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SignatureQualification.INDETERMINATE_ADESIG, simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()));

        Date validationDate = diagnosticData.getValidationDate();
        Date bestSignatureTime = simpleReport.getBestSignatureTime(simpleReport.getFirstSignatureId());
        assertEquals(validationDate, bestSignatureTime);

        assertEquals(4, simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()).size());
        assertEquals(3, simpleReport.getSignatureTimestamps(simpleReport.getFirstSignatureId()).get(0)
                .getAdESValidationDetails().getError().size());

        DetailedReport detailedReport = reports.getDetailedReport();

        eu.europa.esig.dss.detailedreport.jaxb.XmlSignature xmlSignature = detailedReport.getSignatures().get(0);
        XmlValidationProcessArchivalData validationProcessArchivalData = xmlSignature.getValidationProcessArchivalData();
        assertEquals(Indication.INDETERMINATE, validationProcessArchivalData.getConclusion().getIndication());
        assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, validationProcessArchivalData.getConclusion().getSubIndication());

        int tstCheckCounter = 0;
        for (XmlConstraint constraint : validationProcessArchivalData.getConstraint()) {
            if (MessageTag.ADEST_IBSVPTADC.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.WARNING, constraint.getStatus());
                assertEquals(MessageTag.ADEST_IBSVPTADC_ANS.getId(), constraint.getWarning().getKey());
                ++tstCheckCounter;
            }
        }
        assertEquals(0, tstCheckCounter); // skipped, no LTA material

        boolean basicValidationCheckFound = false;
        boolean pastValidationTSTFailedFound = false;

        XmlValidationProcessArchivalDataTimestamp tstValidationProcessArchivalData = xmlSignature.getTimestamps().get(0).getValidationProcessArchivalDataTimestamp();
        assertEquals(Indication.INDETERMINATE, tstValidationProcessArchivalData.getConclusion().getIndication());
        assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, tstValidationProcessArchivalData.getConclusion().getSubIndication());

        List<XmlConstraint> constraints = tstValidationProcessArchivalData.getConstraint();
        for (XmlConstraint constraint : constraints) {
            if (MessageTag.ARCH_IRTVBBA.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
            } else if (MessageTag.ADEST_IBSVPTC.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.WARNING, constraint.getStatus());
                assertEquals(MessageTag.ADEST_IBSVPTC_ANS.getId(), constraint.getWarning().getKey());
                basicValidationCheckFound = true;
            } else if (MessageTag.PSV_IPTVC.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
                assertEquals(MessageTag.PSV_IPTVC_ANS.getId(), constraint.getError().getKey());
                pastValidationTSTFailedFound = true;
            }
        }

        assertTrue(basicValidationCheckFound);
        assertTrue(pastValidationTSTFailedFound);

        validateBestSigningTimes(reports);
        checkReports(reports);
    }

}
