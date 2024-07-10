package eu.europa.esig.dss.validation.executor.process;

import eu.europa.esig.dss.detailedreport.DetailedReport;
import eu.europa.esig.dss.detailedreport.jaxb.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.detailedreport.jaxb.XmlCV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.diagnostic.DiagnosticDataFacade;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.ValidationPolicy;
import eu.europa.esig.dss.policy.jaxb.BasicSignatureConstraints;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.validation.executor.signature.DefaultSignatureProcessExecutor;
import eu.europa.esig.dss.validation.reports.Reports;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.util.Iterator;
import java.util.List;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ManifestEntriesValidationExecutorTest extends AbstractProcessExecutorTest {

    @Test
    void detachedDocNameDoNotMatchWarnLevel() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/DSS-1453/diag-data-lta-dss.xml"));
        assertNotNull(diagnosticData);

        XmlDigestMatcher digestMatcher = diagnosticData.getSignatures().get(0).getDigestMatchers().get(0);
        digestMatcher.setDocumentName("wrong-name.xml");

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.WARN);
        validationPolicy.getSignatureConstraints().getBasicSignatureConstraints().setReferenceDataNameMatch(levelConstraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();
        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationWarnings(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_CV_DRNMND_ANS)));

        DetailedReport detailedReport = reports.getDetailedReport();
        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertEquals(Indication.PASSED, signatureBBB.getConclusion().getIndication());
        assertTrue(checkMessageValuePresence(convert(signatureBBB.getConclusion().getWarnings()),
                i18nProvider.getMessage(MessageTag.BBB_CV_DRNMND_ANS)));

        XmlCV cv = signatureBBB.getCV();
        assertNotNull(cv);
        assertEquals(Indication.PASSED, cv.getConclusion().getIndication());

        int nameCheckCounter = 0;
        for (XmlConstraint constraint : cv.getConstraint()) {
            if (MessageTag.BBB_CV_DRNMND.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.WARNING, constraint.getStatus());
                assertEquals(MessageTag.BBB_CV_DRNMND_ANS.getId(), constraint.getWarning().getKey());
                assertEquals(i18nProvider.getMessage(MessageTag.REFERENCE_NAME_CHECK, digestMatcher.getUri(), digestMatcher.getDocumentName()),
                        constraint.getAdditionalInfo());
                ++nameCheckCounter;
            }
        }
        assertEquals(1, nameCheckCounter);

        checkReports(reports);
    }

    @Test
    void detachedDocNameDoNotMatchFailLevel() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/DSS-1453/diag-data-lta-dss.xml"));
        assertNotNull(diagnosticData);

        XmlDigestMatcher digestMatcher = diagnosticData.getSignatures().get(0).getDigestMatchers().get(0);
        digestMatcher.setDocumentName("wrong-name.xml");

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.FAIL);
        validationPolicy.getSignatureConstraints().getBasicSignatureConstraints().setReferenceDataNameMatch(levelConstraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();
        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.SIGNED_DATA_NOT_FOUND, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_CV_DRNMND_ANS)));

        DetailedReport detailedReport = reports.getDetailedReport();
        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertEquals(Indication.INDETERMINATE, signatureBBB.getConclusion().getIndication());
        assertEquals(SubIndication.SIGNED_DATA_NOT_FOUND, signatureBBB.getConclusion().getSubIndication());
        assertTrue(checkMessageValuePresence(convert(signatureBBB.getConclusion().getErrors()),
                i18nProvider.getMessage(MessageTag.BBB_CV_DRNMND_ANS)));

        XmlCV cv = signatureBBB.getCV();
        assertNotNull(cv);
        assertEquals(Indication.INDETERMINATE, cv.getConclusion().getIndication());
        assertEquals(SubIndication.SIGNED_DATA_NOT_FOUND, cv.getConclusion().getSubIndication());

        int nameCheckCounter = 0;
        for (XmlConstraint constraint : cv.getConstraint()) {
            if (MessageTag.BBB_CV_DRNMND.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
                assertEquals(MessageTag.BBB_CV_DRNMND_ANS.getId(), constraint.getError().getKey());
                assertEquals(i18nProvider.getMessage(MessageTag.REFERENCE_NAME_CHECK, digestMatcher.getUri(), digestMatcher.getDocumentName()),
                        constraint.getAdditionalInfo());
                ++nameCheckCounter;
            }
        }
        assertEquals(1, nameCheckCounter);

        checkReports(reports);
    }

    @Test
    void asicManifestEntryNotPresent() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/mra/diag-data-mra-with-qtsts.xml"));
        assertNotNull(diagnosticData);

        XmlDigestMatcher digestMatcher = diagnosticData.getSignatures().get(0).getDigestMatchers().get(1);
        digestMatcher.setDataFound(false);
        digestMatcher.setDataIntact(false);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();
        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.SIGNED_DATA_NOT_FOUND, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_CV_IMEOF_ANS)));

        DetailedReport detailedReport = reports.getDetailedReport();
        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertEquals(Indication.INDETERMINATE, signatureBBB.getConclusion().getIndication());
        assertEquals(SubIndication.SIGNED_DATA_NOT_FOUND, signatureBBB.getConclusion().getSubIndication());
        assertTrue(checkMessageValuePresence(convert(signatureBBB.getConclusion().getErrors()),
                i18nProvider.getMessage(MessageTag.BBB_CV_IMEOF_ANS)));

        XmlCV cv = signatureBBB.getCV();
        assertNotNull(cv);
        assertEquals(Indication.INDETERMINATE, cv.getConclusion().getIndication());
        assertEquals(SubIndication.SIGNED_DATA_NOT_FOUND, cv.getConclusion().getSubIndication());

        int digestMatcherFoundCounter = 0;
        for (XmlConstraint constraint : cv.getConstraint()) {
            if (MessageTag.BBB_CV_IMEOF.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
                assertEquals(MessageTag.BBB_CV_IMEOF_ANS.getId(), constraint.getError().getKey());
                assertEquals(i18nProvider.getMessage(MessageTag.REFERENCE, digestMatcher.getUri()),
                        constraint.getAdditionalInfo());
                ++digestMatcherFoundCounter;
            }
        }
        assertEquals(1, digestMatcherFoundCounter);

        checkReports(reports);
    }

    @Test
    void asicManifestEntryNotIntact() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/mra/diag-data-mra-with-qtsts.xml"));
        assertNotNull(diagnosticData);

        XmlDigestMatcher digestMatcher = diagnosticData.getSignatures().get(0).getDigestMatchers().get(1);
        digestMatcher.setDataFound(true);
        digestMatcher.setDataIntact(false);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();
        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_FAILED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.HASH_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_CV_IMEDOI_ANS)));

        DetailedReport detailedReport = reports.getDetailedReport();
        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertEquals(Indication.FAILED, signatureBBB.getConclusion().getIndication());
        assertEquals(SubIndication.HASH_FAILURE, signatureBBB.getConclusion().getSubIndication());
        assertTrue(checkMessageValuePresence(convert(signatureBBB.getConclusion().getErrors()),
                i18nProvider.getMessage(MessageTag.BBB_CV_IMEDOI_ANS)));

        XmlCV cv = signatureBBB.getCV();
        assertNotNull(cv);
        assertEquals(Indication.FAILED, cv.getConclusion().getIndication());
        assertEquals(SubIndication.HASH_FAILURE, cv.getConclusion().getSubIndication());

        int digestMatcherFoundCounter = 0;
        int digestMatcherIntactCounter = 0;
        for (XmlConstraint constraint : cv.getConstraint()) {
            if (MessageTag.BBB_CV_IMEOF.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                ++digestMatcherFoundCounter;
            } else if (MessageTag.BBB_CV_IMEDOI.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
                assertEquals(MessageTag.BBB_CV_IMEDOI_ANS.getId(), constraint.getError().getKey());
                assertEquals(i18nProvider.getMessage(MessageTag.REFERENCE, digestMatcher.getUri()),
                        constraint.getAdditionalInfo());
                ++digestMatcherIntactCounter;
            }
        }
        assertEquals(1, digestMatcherFoundCounter);
        assertEquals(1, digestMatcherIntactCounter);

        checkReports(reports);
    }

    @Test
    void manifestValidationAllStrictPass() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_many_references.xml"));
        assertNotNull(diagnosticData);

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        BasicSignatureConstraints basicSignatureConstraints = validationPolicy.getSignatureConstraints().getBasicSignatureConstraints();

        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.FAIL);
        basicSignatureConstraints.setManifestEntryObjectExistence(levelConstraint);
        basicSignatureConstraints.setManifestEntryObjectGroup(levelConstraint);
        basicSignatureConstraints.setManifestEntryObjectIntact(levelConstraint);
        basicSignatureConstraints.setManifestEntryNameMatch(levelConstraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();
        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));

        DetailedReport detailedReport = reports.getDetailedReport();
        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertEquals(Indication.PASSED, signatureBBB.getConclusion().getIndication());

        XmlCV cv = signatureBBB.getCV();
        assertNotNull(cv);
        assertEquals(Indication.PASSED, cv.getConclusion().getIndication());

        int digestMatcherValidationPerformedCounter = 0;
        int allDigestMatcherFoundCounter = 0;
        int digestMatcherIntactCounter = 0;
        int digestMatcherNameCounter = 0;
        for (XmlConstraint constraint : cv.getConstraint()) {
            if (MessageTag.BBB_CV_ISMEC.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                ++digestMatcherValidationPerformedCounter;
            } else if (MessageTag.BBB_CV_AAMEF.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                ++allDigestMatcherFoundCounter;
            } else if (MessageTag.BBB_CV_IMEDOI.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                ++digestMatcherIntactCounter;
            } else if (MessageTag.BBB_CV_DMENMND.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                ++digestMatcherNameCounter;
            }
        }
        assertEquals(1, digestMatcherValidationPerformedCounter);
        assertEquals(1, allDigestMatcherFoundCounter);
        assertEquals(24, digestMatcherIntactCounter);
        assertEquals(24, digestMatcherNameCounter);

        checkReports(reports);
    }

    @Test
    void manifestValidationAllStrictNameNoMatch() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_many_references.xml"));
        assertNotNull(diagnosticData);

        List<XmlDigestMatcher> digestMatchers = diagnosticData.getSignatures().get(0).getDigestMatchers();
        XmlDigestMatcher digestMatcher = digestMatchers.get(digestMatchers.size() - 2);
        digestMatcher.setDocumentName("wrong-name.pdf");

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        BasicSignatureConstraints basicSignatureConstraints = validationPolicy.getSignatureConstraints().getBasicSignatureConstraints();

        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.FAIL);
        basicSignatureConstraints.setManifestEntryObjectExistence(levelConstraint);
        basicSignatureConstraints.setManifestEntryObjectGroup(levelConstraint);
        basicSignatureConstraints.setManifestEntryObjectIntact(levelConstraint);
        basicSignatureConstraints.setManifestEntryNameMatch(levelConstraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();
        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.SIGNED_DATA_NOT_FOUND, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_CV_DMENMND_ANS)));

        DetailedReport detailedReport = reports.getDetailedReport();
        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertEquals(Indication.INDETERMINATE, signatureBBB.getConclusion().getIndication());
        assertEquals(SubIndication.SIGNED_DATA_NOT_FOUND, signatureBBB.getConclusion().getSubIndication());

        XmlCV cv = signatureBBB.getCV();
        assertNotNull(cv);
        assertEquals(Indication.INDETERMINATE, cv.getConclusion().getIndication());
        assertEquals(SubIndication.SIGNED_DATA_NOT_FOUND, cv.getConclusion().getSubIndication());

        int digestMatcherValidationPerformedCounter = 0;
        int allDigestMatcherFoundCounter = 0;
        int digestMatcherIntactCounter = 0;
        int digestMatcherNameValidCounter = 0;
        int digestMatcherNameInvalidCounter = 0;
        for (XmlConstraint constraint : cv.getConstraint()) {
            if (MessageTag.BBB_CV_ISMEC.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                ++digestMatcherValidationPerformedCounter;
            } else if (MessageTag.BBB_CV_AAMEF.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                ++allDigestMatcherFoundCounter;
            } else if (MessageTag.BBB_CV_IMEDOI.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                ++digestMatcherIntactCounter;
            } else if (MessageTag.BBB_CV_DMENMND.getId().equals(constraint.getName().getKey())) {
                if (XmlStatus.OK == constraint.getStatus()) {
                    ++ digestMatcherNameValidCounter;
                } else if (XmlStatus.NOT_OK == constraint.getStatus()) {
                    assertEquals(MessageTag.BBB_CV_DMENMND_ANS.getId(), constraint.getError().getKey());
                    ++digestMatcherNameInvalidCounter;
                }
            }
        }
        assertEquals(1, digestMatcherValidationPerformedCounter);
        assertEquals(1, allDigestMatcherFoundCounter);
        assertEquals(24, digestMatcherIntactCounter);
        assertEquals(23, digestMatcherNameValidCounter);
        assertEquals(1, digestMatcherNameInvalidCounter);

        checkReports(reports);
    }

    @Test
    void manifestValidationAllStrictNoIntact() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_many_references.xml"));
        assertNotNull(diagnosticData);

        List<XmlDigestMatcher> digestMatchers = diagnosticData.getSignatures().get(0).getDigestMatchers();
        XmlDigestMatcher digestMatcher = digestMatchers.get(digestMatchers.size() - 2);
        digestMatcher.setDataIntact(false);

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        BasicSignatureConstraints basicSignatureConstraints = validationPolicy.getSignatureConstraints().getBasicSignatureConstraints();

        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.FAIL);
        basicSignatureConstraints.setManifestEntryObjectExistence(levelConstraint);
        basicSignatureConstraints.setManifestEntryObjectGroup(levelConstraint);
        basicSignatureConstraints.setManifestEntryObjectIntact(levelConstraint);
        basicSignatureConstraints.setManifestEntryNameMatch(levelConstraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();
        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_FAILED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.HASH_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_CV_IMEDOI_ANS)));

        DetailedReport detailedReport = reports.getDetailedReport();
        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertEquals(Indication.FAILED, signatureBBB.getConclusion().getIndication());
        assertEquals(SubIndication.HASH_FAILURE, signatureBBB.getConclusion().getSubIndication());

        XmlCV cv = signatureBBB.getCV();
        assertNotNull(cv);
        assertEquals(Indication.FAILED, cv.getConclusion().getIndication());
        assertEquals(SubIndication.HASH_FAILURE, cv.getConclusion().getSubIndication());

        int digestMatcherValidationPerformedCounter = 0;
        int allDigestMatcherFoundCounter = 0;
        int digestMatcherIntactValidCounter = 0;
        int digestMatcherIntactInvalidCounter = 0;
        int digestMatcherNameCounter = 0;
        for (XmlConstraint constraint : cv.getConstraint()) {
            if (MessageTag.BBB_CV_ISMEC.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                ++digestMatcherValidationPerformedCounter;
            } else if (MessageTag.BBB_CV_AAMEF.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                ++allDigestMatcherFoundCounter;
            } else if (MessageTag.BBB_CV_IMEDOI.getId().equals(constraint.getName().getKey())) {
                if (XmlStatus.OK == constraint.getStatus()) {
                    ++ digestMatcherIntactValidCounter;
                } else if (XmlStatus.NOT_OK == constraint.getStatus()) {
                    assertEquals(MessageTag.BBB_CV_IMEDOI_ANS.getId(), constraint.getError().getKey());
                    ++digestMatcherIntactInvalidCounter;
                }
            } else if (MessageTag.BBB_CV_DMENMND.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                ++digestMatcherNameCounter;
            }
        }
        assertEquals(1, digestMatcherValidationPerformedCounter);
        assertEquals(1, allDigestMatcherFoundCounter);
        assertEquals(23, digestMatcherIntactValidCounter);
        assertEquals(1, digestMatcherIntactInvalidCounter);
        assertEquals(23, digestMatcherNameCounter);

        checkReports(reports);
    }

    @Test
    void manifestValidationAllStrictNoFound() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_many_references.xml"));
        assertNotNull(diagnosticData);

        List<XmlDigestMatcher> digestMatchers = diagnosticData.getSignatures().get(0).getDigestMatchers();
        XmlDigestMatcher digestMatcher = digestMatchers.get(digestMatchers.size() - 2);
        digestMatcher.setDataFound(false);
        digestMatcher.setDataIntact(false);

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        BasicSignatureConstraints basicSignatureConstraints = validationPolicy.getSignatureConstraints().getBasicSignatureConstraints();

        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.FAIL);
        basicSignatureConstraints.setManifestEntryObjectExistence(levelConstraint);
        basicSignatureConstraints.setManifestEntryObjectGroup(levelConstraint);
        basicSignatureConstraints.setManifestEntryObjectIntact(levelConstraint);
        basicSignatureConstraints.setManifestEntryNameMatch(levelConstraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();
        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.SIGNED_DATA_NOT_FOUND, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_CV_AAMEF_ANS)));

        DetailedReport detailedReport = reports.getDetailedReport();
        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertEquals(Indication.INDETERMINATE, signatureBBB.getConclusion().getIndication());
        assertEquals(SubIndication.SIGNED_DATA_NOT_FOUND, signatureBBB.getConclusion().getSubIndication());

        XmlCV cv = signatureBBB.getCV();
        assertNotNull(cv);
        assertEquals(Indication.INDETERMINATE, cv.getConclusion().getIndication());
        assertEquals(SubIndication.SIGNED_DATA_NOT_FOUND, cv.getConclusion().getSubIndication());

        int digestMatcherValidationPerformedCounter = 0;
        int allDigestMatcherFoundValidCounter = 0;
        int allDigestMatcherFoundInvalidCounter = 0;
        int digestMatcherIntactCounter = 0;
        int digestMatcherNameCounter = 0;
        for (XmlConstraint constraint : cv.getConstraint()) {
            if (MessageTag.BBB_CV_ISMEC.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                ++digestMatcherValidationPerformedCounter;
            } else if (MessageTag.BBB_CV_AAMEF.getId().equals(constraint.getName().getKey())) {
                if (XmlStatus.OK == constraint.getStatus()) {
                    ++ allDigestMatcherFoundValidCounter;
                } else if (XmlStatus.NOT_OK == constraint.getStatus()) {
                    assertEquals(MessageTag.BBB_CV_AAMEF_ANS.getId(), constraint.getError().getKey());
                    assertEquals(i18nProvider.getMessage(MessageTag.REFERENCES_WITH_NAMES, digestMatcher.getUri()),
                            constraint.getAdditionalInfo());
                    ++allDigestMatcherFoundInvalidCounter;
                }
            } else if (MessageTag.BBB_CV_IMEDOI.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                ++digestMatcherIntactCounter;
            } else if (MessageTag.BBB_CV_DMENMND.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                ++digestMatcherNameCounter;
            }
        }
        assertEquals(1, digestMatcherValidationPerformedCounter);
        assertEquals(0, allDigestMatcherFoundValidCounter);
        assertEquals(1, allDigestMatcherFoundInvalidCounter);
        assertEquals(0, digestMatcherIntactCounter);
        assertEquals(0, digestMatcherNameCounter);

        checkReports(reports);
    }

    @Test
    void manifestValidationAllStrictNoFoundAll() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_many_references.xml"));
        assertNotNull(diagnosticData);

        List<XmlDigestMatcher> digestMatchers = diagnosticData.getSignatures().get(0).getDigestMatchers();
        digestMatchers = digestMatchers.stream().filter(d -> DigestMatcherType.MANIFEST_ENTRY == d.getType()).collect(Collectors.toList());
        for (XmlDigestMatcher digestMatcher : digestMatchers) {
            digestMatcher.setDocumentName(null);
            digestMatcher.setDataFound(false);
            digestMatcher.setDataIntact(false);
        }

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        BasicSignatureConstraints basicSignatureConstraints = validationPolicy.getSignatureConstraints().getBasicSignatureConstraints();

        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.FAIL);
        basicSignatureConstraints.setManifestEntryObjectExistence(levelConstraint);
        basicSignatureConstraints.setManifestEntryObjectGroup(levelConstraint);
        basicSignatureConstraints.setManifestEntryObjectIntact(levelConstraint);
        basicSignatureConstraints.setManifestEntryNameMatch(levelConstraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();
        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.SIGNED_DATA_NOT_FOUND, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_CV_ISMEC_ANS)));

        DetailedReport detailedReport = reports.getDetailedReport();
        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertEquals(Indication.INDETERMINATE, signatureBBB.getConclusion().getIndication());
        assertEquals(SubIndication.SIGNED_DATA_NOT_FOUND, signatureBBB.getConclusion().getSubIndication());

        XmlCV cv = signatureBBB.getCV();
        assertNotNull(cv);
        assertEquals(Indication.INDETERMINATE, cv.getConclusion().getIndication());
        assertEquals(SubIndication.SIGNED_DATA_NOT_FOUND, cv.getConclusion().getSubIndication());

        int digestMatcherValidationPerformedCounter = 0;
        int allDigestMatcherFoundCounter = 0;
        int digestMatcherIntactCounter = 0;
        int digestMatcherNameCounter = 0;
        for (XmlConstraint constraint : cv.getConstraint()) {
            if (MessageTag.BBB_CV_ISMEC.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
                assertEquals(MessageTag.BBB_CV_ISMEC_ANS.getId(), constraint.getError().getKey());
                ++digestMatcherValidationPerformedCounter;
            } else if (MessageTag.BBB_CV_AAMEF.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                ++allDigestMatcherFoundCounter;
            } else if (MessageTag.BBB_CV_IMEDOI.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                ++digestMatcherIntactCounter;
            } else if (MessageTag.BBB_CV_DMENMND.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                ++digestMatcherNameCounter;
            }
        }
        assertEquals(1, digestMatcherValidationPerformedCounter);
        assertEquals(0, allDigestMatcherFoundCounter);
        assertEquals(0, digestMatcherIntactCounter);
        assertEquals(0, digestMatcherNameCounter);

        checkReports(reports);
    }

    @Test
    void manifestValidationAllStrictEntriesNotPresent() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_many_references.xml"));
        assertNotNull(diagnosticData);

        List<XmlDigestMatcher> digestMatchers = diagnosticData.getSignatures().get(0).getDigestMatchers();
        Iterator<XmlDigestMatcher> iterator = digestMatchers.iterator();
        while (iterator.hasNext()) {
            XmlDigestMatcher digestMatcher = iterator.next();
            if (DigestMatcherType.MANIFEST_ENTRY == digestMatcher.getType()) {
                iterator.remove();
            }
        }

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        BasicSignatureConstraints basicSignatureConstraints = validationPolicy.getSignatureConstraints().getBasicSignatureConstraints();

        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.FAIL);
        basicSignatureConstraints.setManifestEntryObjectExistence(levelConstraint);
        basicSignatureConstraints.setManifestEntryObjectGroup(levelConstraint);
        basicSignatureConstraints.setManifestEntryObjectIntact(levelConstraint);
        basicSignatureConstraints.setManifestEntryNameMatch(levelConstraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();
        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.SIGNED_DATA_NOT_FOUND, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_CV_ISMEC_ANS)));

        DetailedReport detailedReport = reports.getDetailedReport();
        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertEquals(Indication.INDETERMINATE, signatureBBB.getConclusion().getIndication());
        assertEquals(SubIndication.SIGNED_DATA_NOT_FOUND, signatureBBB.getConclusion().getSubIndication());

        XmlCV cv = signatureBBB.getCV();
        assertNotNull(cv);
        assertEquals(Indication.INDETERMINATE, cv.getConclusion().getIndication());
        assertEquals(SubIndication.SIGNED_DATA_NOT_FOUND, cv.getConclusion().getSubIndication());

        int digestMatcherValidationPerformedCounter = 0;
        int allDigestMatcherFoundCounter = 0;
        int digestMatcherIntactCounter = 0;
        int digestMatcherNameCounter = 0;
        for (XmlConstraint constraint : cv.getConstraint()) {
            if (MessageTag.BBB_CV_ISMEC.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
                assertEquals(MessageTag.BBB_CV_ISMEC_ANS.getId(), constraint.getError().getKey());
                ++digestMatcherValidationPerformedCounter;
            } else if (MessageTag.BBB_CV_AAMEF.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                ++allDigestMatcherFoundCounter;
            } else if (MessageTag.BBB_CV_IMEDOI.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                ++digestMatcherIntactCounter;
            } else if (MessageTag.BBB_CV_DMENMND.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                ++digestMatcherNameCounter;
            }
        }
        assertEquals(1, digestMatcherValidationPerformedCounter);
        assertEquals(0, allDigestMatcherFoundCounter);
        assertEquals(0, digestMatcherIntactCounter);
        assertEquals(0, digestMatcherNameCounter);

        checkReports(reports);
    }

    @Test
    void manifestValidationAllLaxPass() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_many_references.xml"));
        assertNotNull(diagnosticData);

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        BasicSignatureConstraints basicSignatureConstraints = validationPolicy.getSignatureConstraints().getBasicSignatureConstraints();

        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.FAIL);
        basicSignatureConstraints.setManifestEntryObjectExistence(levelConstraint);
        basicSignatureConstraints.setManifestEntryObjectGroup(levelConstraint);
        basicSignatureConstraints.setManifestEntryObjectIntact(levelConstraint);

        LevelConstraint levelWarn = new LevelConstraint();
        levelWarn.setLevel(Level.WARN);
        basicSignatureConstraints.setManifestEntryNameMatch(levelWarn);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();
        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));

        DetailedReport detailedReport = reports.getDetailedReport();
        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertEquals(Indication.PASSED, signatureBBB.getConclusion().getIndication());

        XmlCV cv = signatureBBB.getCV();
        assertNotNull(cv);
        assertEquals(Indication.PASSED, cv.getConclusion().getIndication());

        int digestMatcherValidationPerformedCounter = 0;
        int allDigestMatcherFoundCounter = 0;
        int digestMatcherIntactCounter = 0;
        int digestMatcherNameCounter = 0;
        for (XmlConstraint constraint : cv.getConstraint()) {
            if (MessageTag.BBB_CV_ISMEC.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                ++digestMatcherValidationPerformedCounter;
            } else if (MessageTag.BBB_CV_AAMEF.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                ++allDigestMatcherFoundCounter;
            } else if (MessageTag.BBB_CV_IMEDOI.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                ++digestMatcherIntactCounter;
            } else if (MessageTag.BBB_CV_DMENMND.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                ++digestMatcherNameCounter;
            }
        }
        assertEquals(1, digestMatcherValidationPerformedCounter);
        assertEquals(1, allDigestMatcherFoundCounter);
        assertEquals(24, digestMatcherIntactCounter);
        assertEquals(24, digestMatcherNameCounter);

        checkReports(reports);
    }

    @Test
    void manifestValidationAllLaxNameNoMatch() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_many_references.xml"));
        assertNotNull(diagnosticData);

        List<XmlDigestMatcher> digestMatchers = diagnosticData.getSignatures().get(0).getDigestMatchers();
        XmlDigestMatcher digestMatcher = digestMatchers.get(digestMatchers.size() - 2);
        digestMatcher.setDocumentName("wrong-name.pdf");

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        BasicSignatureConstraints basicSignatureConstraints = validationPolicy.getSignatureConstraints().getBasicSignatureConstraints();

        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.FAIL);
        basicSignatureConstraints.setManifestEntryObjectExistence(levelConstraint);
        basicSignatureConstraints.setManifestEntryObjectGroup(levelConstraint);
        basicSignatureConstraints.setManifestEntryObjectIntact(levelConstraint);

        LevelConstraint levelWarn = new LevelConstraint();
        levelWarn.setLevel(Level.WARN);
        basicSignatureConstraints.setManifestEntryNameMatch(levelWarn);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();
        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationWarnings(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_CV_DMENMND_ANS)));

        DetailedReport detailedReport = reports.getDetailedReport();
        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));

        XmlCV cv = signatureBBB.getCV();
        assertNotNull(cv);
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));

        int digestMatcherValidationPerformedCounter = 0;
        int allDigestMatcherFoundCounter = 0;
        int digestMatcherIntactCounter = 0;
        int digestMatcherNameValidCounter = 0;
        int digestMatcherNameInvalidCounter = 0;
        for (XmlConstraint constraint : cv.getConstraint()) {
            if (MessageTag.BBB_CV_ISMEC.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                ++digestMatcherValidationPerformedCounter;
            } else if (MessageTag.BBB_CV_AAMEF.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                ++allDigestMatcherFoundCounter;
            } else if (MessageTag.BBB_CV_IMEDOI.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                ++digestMatcherIntactCounter;
            } else if (MessageTag.BBB_CV_DMENMND.getId().equals(constraint.getName().getKey())) {
                if (XmlStatus.OK == constraint.getStatus()) {
                    ++ digestMatcherNameValidCounter;
                } else if (XmlStatus.WARNING == constraint.getStatus()) {
                    assertEquals(MessageTag.BBB_CV_DMENMND_ANS.getId(), constraint.getWarning().getKey());
                    ++digestMatcherNameInvalidCounter;
                }
            }
        }
        assertEquals(1, digestMatcherValidationPerformedCounter);
        assertEquals(1, allDigestMatcherFoundCounter);
        assertEquals(24, digestMatcherIntactCounter);
        assertEquals(23, digestMatcherNameValidCounter);
        assertEquals(1, digestMatcherNameInvalidCounter);

        checkReports(reports);
    }

    @Test
    void manifestValidationAllLaxNoIntact() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_many_references.xml"));
        assertNotNull(diagnosticData);

        List<XmlDigestMatcher> digestMatchers = diagnosticData.getSignatures().get(0).getDigestMatchers();
        XmlDigestMatcher digestMatcher = digestMatchers.get(digestMatchers.size() - 2);
        digestMatcher.setDataIntact(false);

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        BasicSignatureConstraints basicSignatureConstraints = validationPolicy.getSignatureConstraints().getBasicSignatureConstraints();

        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.FAIL);
        basicSignatureConstraints.setManifestEntryObjectExistence(levelConstraint);
        basicSignatureConstraints.setManifestEntryObjectGroup(levelConstraint);
        basicSignatureConstraints.setManifestEntryObjectIntact(levelConstraint);

        LevelConstraint levelWarn = new LevelConstraint();
        levelWarn.setLevel(Level.WARN);
        basicSignatureConstraints.setManifestEntryNameMatch(levelWarn);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();
        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_FAILED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.HASH_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_CV_IMEDOI_ANS)));

        DetailedReport detailedReport = reports.getDetailedReport();
        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertEquals(Indication.FAILED, signatureBBB.getConclusion().getIndication());
        assertEquals(SubIndication.HASH_FAILURE, signatureBBB.getConclusion().getSubIndication());

        XmlCV cv = signatureBBB.getCV();
        assertNotNull(cv);
        assertEquals(Indication.FAILED, cv.getConclusion().getIndication());
        assertEquals(SubIndication.HASH_FAILURE, cv.getConclusion().getSubIndication());

        int digestMatcherValidationPerformedCounter = 0;
        int allDigestMatcherFoundCounter = 0;
        int digestMatcherIntactValidCounter = 0;
        int digestMatcherIntactInvalidCounter = 0;
        int digestMatcherNameCounter = 0;
        for (XmlConstraint constraint : cv.getConstraint()) {
            if (MessageTag.BBB_CV_ISMEC.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                ++digestMatcherValidationPerformedCounter;
            } else if (MessageTag.BBB_CV_AAMEF.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                ++allDigestMatcherFoundCounter;
            } else if (MessageTag.BBB_CV_IMEDOI.getId().equals(constraint.getName().getKey())) {
                if (XmlStatus.OK == constraint.getStatus()) {
                    ++ digestMatcherIntactValidCounter;
                } else if (XmlStatus.NOT_OK == constraint.getStatus()) {
                    assertEquals(MessageTag.BBB_CV_IMEDOI_ANS.getId(), constraint.getError().getKey());
                    ++digestMatcherIntactInvalidCounter;
                }
            } else if (MessageTag.BBB_CV_DMENMND.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                ++digestMatcherNameCounter;
            }
        }
        assertEquals(1, digestMatcherValidationPerformedCounter);
        assertEquals(1, allDigestMatcherFoundCounter);
        assertEquals(23, digestMatcherIntactValidCounter);
        assertEquals(1, digestMatcherIntactInvalidCounter);
        assertEquals(23, digestMatcherNameCounter);

        checkReports(reports);
    }

    @Test
    void manifestValidationAllLaxNoFound() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_many_references.xml"));
        assertNotNull(diagnosticData);

        List<XmlDigestMatcher> digestMatchers = diagnosticData.getSignatures().get(0).getDigestMatchers();
        XmlDigestMatcher digestMatcher = digestMatchers.get(digestMatchers.size() - 2);
        digestMatcher.setDataFound(false);
        digestMatcher.setDataIntact(false);

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        BasicSignatureConstraints basicSignatureConstraints = validationPolicy.getSignatureConstraints().getBasicSignatureConstraints();

        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.FAIL);
        basicSignatureConstraints.setManifestEntryObjectExistence(levelConstraint);
        basicSignatureConstraints.setManifestEntryObjectGroup(levelConstraint);
        basicSignatureConstraints.setManifestEntryObjectIntact(levelConstraint);

        LevelConstraint levelWarn = new LevelConstraint();
        levelWarn.setLevel(Level.WARN);
        basicSignatureConstraints.setManifestEntryNameMatch(levelWarn);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();
        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.SIGNED_DATA_NOT_FOUND, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_CV_AAMEF_ANS)));

        DetailedReport detailedReport = reports.getDetailedReport();
        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertEquals(Indication.INDETERMINATE, signatureBBB.getConclusion().getIndication());
        assertEquals(SubIndication.SIGNED_DATA_NOT_FOUND, signatureBBB.getConclusion().getSubIndication());

        XmlCV cv = signatureBBB.getCV();
        assertNotNull(cv);
        assertEquals(Indication.INDETERMINATE, cv.getConclusion().getIndication());
        assertEquals(SubIndication.SIGNED_DATA_NOT_FOUND, cv.getConclusion().getSubIndication());

        int digestMatcherValidationPerformedCounter = 0;
        int allDigestMatcherFoundValidCounter = 0;
        int allDigestMatcherFoundInvalidCounter = 0;
        int digestMatcherIntactCounter = 0;
        int digestMatcherNameCounter = 0;
        for (XmlConstraint constraint : cv.getConstraint()) {
            if (MessageTag.BBB_CV_ISMEC.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                ++digestMatcherValidationPerformedCounter;
            } else if (MessageTag.BBB_CV_AAMEF.getId().equals(constraint.getName().getKey())) {
                if (XmlStatus.OK == constraint.getStatus()) {
                    ++ allDigestMatcherFoundValidCounter;
                } else if (XmlStatus.NOT_OK == constraint.getStatus()) {
                    assertEquals(MessageTag.BBB_CV_AAMEF_ANS.getId(), constraint.getError().getKey());
                    assertEquals(i18nProvider.getMessage(MessageTag.REFERENCES_WITH_NAMES, digestMatcher.getUri()),
                            constraint.getAdditionalInfo());
                    ++allDigestMatcherFoundInvalidCounter;
                }
            } else if (MessageTag.BBB_CV_IMEDOI.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                ++digestMatcherIntactCounter;
            } else if (MessageTag.BBB_CV_DMENMND.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                ++digestMatcherNameCounter;
            }
        }
        assertEquals(1, digestMatcherValidationPerformedCounter);
        assertEquals(0, allDigestMatcherFoundValidCounter);
        assertEquals(1, allDigestMatcherFoundInvalidCounter);
        assertEquals(0, digestMatcherIntactCounter);
        assertEquals(0, digestMatcherNameCounter);

        checkReports(reports);
    }

    @Test
    void manifestValidationAllLaxNoFoundAll() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_many_references.xml"));
        assertNotNull(diagnosticData);

        List<XmlDigestMatcher> digestMatchers = diagnosticData.getSignatures().get(0).getDigestMatchers();
        digestMatchers = digestMatchers.stream().filter(d -> DigestMatcherType.MANIFEST_ENTRY == d.getType()).collect(Collectors.toList());
        for (XmlDigestMatcher digestMatcher : digestMatchers) {
            digestMatcher.setDocumentName(null);
            digestMatcher.setDataFound(false);
            digestMatcher.setDataIntact(false);
        }

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        BasicSignatureConstraints basicSignatureConstraints = validationPolicy.getSignatureConstraints().getBasicSignatureConstraints();

        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.FAIL);
        basicSignatureConstraints.setManifestEntryObjectExistence(levelConstraint);
        basicSignatureConstraints.setManifestEntryObjectGroup(levelConstraint);
        basicSignatureConstraints.setManifestEntryObjectIntact(levelConstraint);

        LevelConstraint levelWarn = new LevelConstraint();
        levelWarn.setLevel(Level.WARN);
        basicSignatureConstraints.setManifestEntryNameMatch(levelWarn);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();
        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.SIGNED_DATA_NOT_FOUND, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_CV_ISMEC_ANS)));

        DetailedReport detailedReport = reports.getDetailedReport();
        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertEquals(Indication.INDETERMINATE, signatureBBB.getConclusion().getIndication());
        assertEquals(SubIndication.SIGNED_DATA_NOT_FOUND, signatureBBB.getConclusion().getSubIndication());

        XmlCV cv = signatureBBB.getCV();
        assertNotNull(cv);
        assertEquals(Indication.INDETERMINATE, cv.getConclusion().getIndication());
        assertEquals(SubIndication.SIGNED_DATA_NOT_FOUND, cv.getConclusion().getSubIndication());

        int digestMatcherValidationPerformedCounter = 0;
        int allDigestMatcherFoundCounter = 0;
        int digestMatcherIntactCounter = 0;
        int digestMatcherNameCounter = 0;
        for (XmlConstraint constraint : cv.getConstraint()) {
            if (MessageTag.BBB_CV_ISMEC.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
                assertEquals(MessageTag.BBB_CV_ISMEC_ANS.getId(), constraint.getError().getKey());
                ++digestMatcherValidationPerformedCounter;
            } else if (MessageTag.BBB_CV_AAMEF.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                ++allDigestMatcherFoundCounter;
            } else if (MessageTag.BBB_CV_IMEDOI.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                ++digestMatcherIntactCounter;
            } else if (MessageTag.BBB_CV_DMENMND.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                ++digestMatcherNameCounter;
            }
        }
        assertEquals(1, digestMatcherValidationPerformedCounter);
        assertEquals(0, allDigestMatcherFoundCounter);
        assertEquals(0, digestMatcherIntactCounter);
        assertEquals(0, digestMatcherNameCounter);

        checkReports(reports);
    }

    @Test
    void manifestValidationAllLaxEntriesNotPresent() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_many_references.xml"));
        assertNotNull(diagnosticData);

        List<XmlDigestMatcher> digestMatchers = diagnosticData.getSignatures().get(0).getDigestMatchers();
        Iterator<XmlDigestMatcher> iterator = digestMatchers.iterator();
        while (iterator.hasNext()) {
            XmlDigestMatcher digestMatcher = iterator.next();
            if (DigestMatcherType.MANIFEST_ENTRY == digestMatcher.getType()) {
                iterator.remove();
            }
        }

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        BasicSignatureConstraints basicSignatureConstraints = validationPolicy.getSignatureConstraints().getBasicSignatureConstraints();

        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.FAIL);
        basicSignatureConstraints.setManifestEntryObjectExistence(levelConstraint);
        basicSignatureConstraints.setManifestEntryObjectGroup(levelConstraint);
        basicSignatureConstraints.setManifestEntryObjectIntact(levelConstraint);

        LevelConstraint levelWarn = new LevelConstraint();
        levelWarn.setLevel(Level.WARN);
        basicSignatureConstraints.setManifestEntryNameMatch(levelWarn);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();
        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.SIGNED_DATA_NOT_FOUND, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_CV_ISMEC_ANS)));

        DetailedReport detailedReport = reports.getDetailedReport();
        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertEquals(Indication.INDETERMINATE, signatureBBB.getConclusion().getIndication());
        assertEquals(SubIndication.SIGNED_DATA_NOT_FOUND, signatureBBB.getConclusion().getSubIndication());

        XmlCV cv = signatureBBB.getCV();
        assertNotNull(cv);
        assertEquals(Indication.INDETERMINATE, cv.getConclusion().getIndication());
        assertEquals(SubIndication.SIGNED_DATA_NOT_FOUND, cv.getConclusion().getSubIndication());

        int digestMatcherValidationPerformedCounter = 0;
        int allDigestMatcherFoundCounter = 0;
        int digestMatcherIntactCounter = 0;
        int digestMatcherNameCounter = 0;
        for (XmlConstraint constraint : cv.getConstraint()) {
            if (MessageTag.BBB_CV_ISMEC.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
                assertEquals(MessageTag.BBB_CV_ISMEC_ANS.getId(), constraint.getError().getKey());
                ++digestMatcherValidationPerformedCounter;
            } else if (MessageTag.BBB_CV_AAMEF.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                ++allDigestMatcherFoundCounter;
            } else if (MessageTag.BBB_CV_IMEDOI.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                ++digestMatcherIntactCounter;
            } else if (MessageTag.BBB_CV_DMENMND.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                ++digestMatcherNameCounter;
            }
        }
        assertEquals(1, digestMatcherValidationPerformedCounter);
        assertEquals(0, allDigestMatcherFoundCounter);
        assertEquals(0, digestMatcherIntactCounter);
        assertEquals(0, digestMatcherNameCounter);

        checkReports(reports);
    }

    @Test
    void manifestValidationPartialStrictPass() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_many_references.xml"));
        assertNotNull(diagnosticData);

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        BasicSignatureConstraints basicSignatureConstraints = validationPolicy.getSignatureConstraints().getBasicSignatureConstraints();

        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.FAIL);
        basicSignatureConstraints.setManifestEntryObjectExistence(levelConstraint);
        basicSignatureConstraints.setManifestEntryObjectIntact(levelConstraint);

        LevelConstraint levelWarn = new LevelConstraint();
        levelWarn.setLevel(Level.WARN);
        basicSignatureConstraints.setManifestEntryObjectGroup(levelWarn);

        basicSignatureConstraints.setManifestEntryNameMatch(levelConstraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();
        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));

        DetailedReport detailedReport = reports.getDetailedReport();
        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertEquals(Indication.PASSED, signatureBBB.getConclusion().getIndication());

        XmlCV cv = signatureBBB.getCV();
        assertNotNull(cv);
        assertEquals(Indication.PASSED, cv.getConclusion().getIndication());

        int digestMatcherValidationPerformedCounter = 0;
        int allDigestMatcherFoundCounter = 0;
        int digestMatcherIntactCounter = 0;
        int digestMatcherNameCounter = 0;
        for (XmlConstraint constraint : cv.getConstraint()) {
            if (MessageTag.BBB_CV_ISMEC.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                ++digestMatcherValidationPerformedCounter;
            } else if (MessageTag.BBB_CV_AAMEF.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                ++allDigestMatcherFoundCounter;
            } else if (MessageTag.BBB_CV_IMEDOI.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                ++digestMatcherIntactCounter;
            } else if (MessageTag.BBB_CV_DMENMND.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                ++digestMatcherNameCounter;
            }
        }
        assertEquals(1, digestMatcherValidationPerformedCounter);
        assertEquals(1, allDigestMatcherFoundCounter);
        assertEquals(24, digestMatcherIntactCounter);
        assertEquals(24, digestMatcherNameCounter);

        checkReports(reports);
    }

    @Test
    void manifestValidationPartialStrictNameNoMatch() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_many_references.xml"));
        assertNotNull(diagnosticData);

        List<XmlDigestMatcher> digestMatchers = diagnosticData.getSignatures().get(0).getDigestMatchers();
        XmlDigestMatcher digestMatcher = digestMatchers.get(digestMatchers.size() - 2);
        digestMatcher.setDocumentName("wrong-name.pdf");

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        BasicSignatureConstraints basicSignatureConstraints = validationPolicy.getSignatureConstraints().getBasicSignatureConstraints();

        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.FAIL);
        basicSignatureConstraints.setManifestEntryObjectExistence(levelConstraint);
        basicSignatureConstraints.setManifestEntryObjectIntact(levelConstraint);

        LevelConstraint levelWarn = new LevelConstraint();
        levelWarn.setLevel(Level.WARN);
        basicSignatureConstraints.setManifestEntryObjectGroup(levelWarn);

        basicSignatureConstraints.setManifestEntryNameMatch(levelConstraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();
        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.SIGNED_DATA_NOT_FOUND, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_CV_DMENMND_ANS)));

        DetailedReport detailedReport = reports.getDetailedReport();
        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertEquals(Indication.INDETERMINATE, signatureBBB.getConclusion().getIndication());
        assertEquals(SubIndication.SIGNED_DATA_NOT_FOUND, signatureBBB.getConclusion().getSubIndication());

        XmlCV cv = signatureBBB.getCV();
        assertNotNull(cv);
        assertEquals(Indication.INDETERMINATE, cv.getConclusion().getIndication());
        assertEquals(SubIndication.SIGNED_DATA_NOT_FOUND, cv.getConclusion().getSubIndication());

        int digestMatcherValidationPerformedCounter = 0;
        int allDigestMatcherFoundCounter = 0;
        int digestMatcherIntactCounter = 0;
        int digestMatcherNameValidCounter = 0;
        int digestMatcherNameInvalidCounter = 0;
        for (XmlConstraint constraint : cv.getConstraint()) {
            if (MessageTag.BBB_CV_ISMEC.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                ++digestMatcherValidationPerformedCounter;
            } else if (MessageTag.BBB_CV_AAMEF.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                ++allDigestMatcherFoundCounter;
            } else if (MessageTag.BBB_CV_IMEDOI.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                ++digestMatcherIntactCounter;
            } else if (MessageTag.BBB_CV_DMENMND.getId().equals(constraint.getName().getKey())) {
                if (XmlStatus.OK == constraint.getStatus()) {
                    ++ digestMatcherNameValidCounter;
                } else if (XmlStatus.NOT_OK == constraint.getStatus()) {
                    assertEquals(MessageTag.BBB_CV_DMENMND_ANS.getId(), constraint.getError().getKey());
                    ++digestMatcherNameInvalidCounter;
                }
            }
        }
        assertEquals(1, digestMatcherValidationPerformedCounter);
        assertEquals(1, allDigestMatcherFoundCounter);
        assertEquals(24, digestMatcherIntactCounter);
        assertEquals(23, digestMatcherNameValidCounter);
        assertEquals(1, digestMatcherNameInvalidCounter);

        checkReports(reports);
    }

    @Test
    void manifestValidationPartialStrictNoIntact() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_many_references.xml"));
        assertNotNull(diagnosticData);

        List<XmlDigestMatcher> digestMatchers = diagnosticData.getSignatures().get(0).getDigestMatchers();
        XmlDigestMatcher digestMatcher = digestMatchers.get(digestMatchers.size() - 2);
        digestMatcher.setDataIntact(false);

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        BasicSignatureConstraints basicSignatureConstraints = validationPolicy.getSignatureConstraints().getBasicSignatureConstraints();

        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.FAIL);
        basicSignatureConstraints.setManifestEntryObjectExistence(levelConstraint);
        basicSignatureConstraints.setManifestEntryObjectIntact(levelConstraint);

        LevelConstraint levelWarn = new LevelConstraint();
        levelWarn.setLevel(Level.WARN);
        basicSignatureConstraints.setManifestEntryObjectGroup(levelWarn);

        basicSignatureConstraints.setManifestEntryNameMatch(levelConstraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();
        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_FAILED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.HASH_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_CV_IMEDOI_ANS)));

        DetailedReport detailedReport = reports.getDetailedReport();
        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertEquals(Indication.FAILED, signatureBBB.getConclusion().getIndication());
        assertEquals(SubIndication.HASH_FAILURE, signatureBBB.getConclusion().getSubIndication());

        XmlCV cv = signatureBBB.getCV();
        assertNotNull(cv);
        assertEquals(Indication.FAILED, cv.getConclusion().getIndication());
        assertEquals(SubIndication.HASH_FAILURE, cv.getConclusion().getSubIndication());

        int digestMatcherValidationPerformedCounter = 0;
        int allDigestMatcherFoundCounter = 0;
        int digestMatcherIntactValidCounter = 0;
        int digestMatcherIntactInvalidCounter = 0;
        int digestMatcherNameCounter = 0;
        for (XmlConstraint constraint : cv.getConstraint()) {
            if (MessageTag.BBB_CV_ISMEC.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                ++digestMatcherValidationPerformedCounter;
            } else if (MessageTag.BBB_CV_AAMEF.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                ++allDigestMatcherFoundCounter;
            } else if (MessageTag.BBB_CV_IMEDOI.getId().equals(constraint.getName().getKey())) {
                if (XmlStatus.OK == constraint.getStatus()) {
                    ++ digestMatcherIntactValidCounter;
                } else if (XmlStatus.NOT_OK == constraint.getStatus()) {
                    assertEquals(MessageTag.BBB_CV_IMEDOI_ANS.getId(), constraint.getError().getKey());
                    ++digestMatcherIntactInvalidCounter;
                }
            } else if (MessageTag.BBB_CV_DMENMND.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                ++digestMatcherNameCounter;
            }
        }
        assertEquals(1, digestMatcherValidationPerformedCounter);
        assertEquals(1, allDigestMatcherFoundCounter);
        assertEquals(23, digestMatcherIntactValidCounter);
        assertEquals(1, digestMatcherIntactInvalidCounter);
        assertEquals(23, digestMatcherNameCounter);

        checkReports(reports);
    }

    @Test
    void manifestValidationPartialStrictNoFound() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_many_references.xml"));
        assertNotNull(diagnosticData);

        List<XmlDigestMatcher> digestMatchers = diagnosticData.getSignatures().get(0).getDigestMatchers();
        XmlDigestMatcher digestMatcher = digestMatchers.get(digestMatchers.size() - 2);
        digestMatcher.setDataFound(false);
        digestMatcher.setDataIntact(false);

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        BasicSignatureConstraints basicSignatureConstraints = validationPolicy.getSignatureConstraints().getBasicSignatureConstraints();

        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.FAIL);
        basicSignatureConstraints.setManifestEntryObjectExistence(levelConstraint);
        basicSignatureConstraints.setManifestEntryObjectIntact(levelConstraint);

        LevelConstraint levelWarn = new LevelConstraint();
        levelWarn.setLevel(Level.WARN);
        basicSignatureConstraints.setManifestEntryObjectGroup(levelWarn);

        basicSignatureConstraints.setManifestEntryNameMatch(levelConstraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();
        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationWarnings(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_CV_AAMEF_ANS)));

        DetailedReport detailedReport = reports.getDetailedReport();
        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertEquals(Indication.PASSED, signatureBBB.getConclusion().getIndication());

        XmlCV cv = signatureBBB.getCV();
        assertNotNull(cv);
        assertEquals(Indication.PASSED, cv.getConclusion().getIndication());

        int digestMatcherValidationPerformedCounter = 0;
        int allDigestMatcherFoundValidCounter = 0;
        int allDigestMatcherFoundInvalidCounter = 0;
        int digestMatcherIntactCounter = 0;
        int digestMatcherNameCounter = 0;
        for (XmlConstraint constraint : cv.getConstraint()) {
            if (MessageTag.BBB_CV_ISMEC.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                ++digestMatcherValidationPerformedCounter;
            } else if (MessageTag.BBB_CV_AAMEF.getId().equals(constraint.getName().getKey())) {
                if (XmlStatus.OK == constraint.getStatus()) {
                    ++ allDigestMatcherFoundValidCounter;
                } else if (XmlStatus.WARNING == constraint.getStatus()) {
                    assertEquals(MessageTag.BBB_CV_AAMEF_ANS.getId(), constraint.getWarning().getKey());
                    assertEquals(i18nProvider.getMessage(MessageTag.REFERENCES_WITH_NAMES, digestMatcher.getUri()),
                            constraint.getAdditionalInfo());
                    ++allDigestMatcherFoundInvalidCounter;
                }
            } else if (MessageTag.BBB_CV_IMEDOI.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                ++digestMatcherIntactCounter;
            } else if (MessageTag.BBB_CV_DMENMND.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                ++digestMatcherNameCounter;
            }
        }
        assertEquals(1, digestMatcherValidationPerformedCounter);
        assertEquals(0, allDigestMatcherFoundValidCounter);
        assertEquals(1, allDigestMatcherFoundInvalidCounter);
        assertEquals(23, digestMatcherIntactCounter);
        assertEquals(24, digestMatcherNameCounter);

        checkReports(reports);
    }

    @Test
    void manifestValidationPartialStrictNoFoundAll() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_many_references.xml"));
        assertNotNull(diagnosticData);

        List<XmlDigestMatcher> digestMatchers = diagnosticData.getSignatures().get(0).getDigestMatchers();
        digestMatchers = digestMatchers.stream().filter(d -> DigestMatcherType.MANIFEST_ENTRY == d.getType()).collect(Collectors.toList());
        for (XmlDigestMatcher digestMatcher : digestMatchers) {
            digestMatcher.setDocumentName(null);
            digestMatcher.setDataFound(false);
            digestMatcher.setDataIntact(false);
        }

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        BasicSignatureConstraints basicSignatureConstraints = validationPolicy.getSignatureConstraints().getBasicSignatureConstraints();

        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.FAIL);
        basicSignatureConstraints.setManifestEntryObjectExistence(levelConstraint);
        basicSignatureConstraints.setManifestEntryObjectIntact(levelConstraint);

        LevelConstraint levelWarn = new LevelConstraint();
        levelWarn.setLevel(Level.WARN);
        basicSignatureConstraints.setManifestEntryObjectGroup(levelWarn);

        basicSignatureConstraints.setManifestEntryNameMatch(levelConstraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();
        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.SIGNED_DATA_NOT_FOUND, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_CV_ISMEC_ANS)));

        DetailedReport detailedReport = reports.getDetailedReport();
        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertEquals(Indication.INDETERMINATE, signatureBBB.getConclusion().getIndication());
        assertEquals(SubIndication.SIGNED_DATA_NOT_FOUND, signatureBBB.getConclusion().getSubIndication());

        XmlCV cv = signatureBBB.getCV();
        assertNotNull(cv);
        assertEquals(Indication.INDETERMINATE, cv.getConclusion().getIndication());
        assertEquals(SubIndication.SIGNED_DATA_NOT_FOUND, cv.getConclusion().getSubIndication());

        int digestMatcherValidationPerformedCounter = 0;
        int allDigestMatcherFoundCounter = 0;
        int digestMatcherIntactCounter = 0;
        int digestMatcherNameCounter = 0;
        for (XmlConstraint constraint : cv.getConstraint()) {
            if (MessageTag.BBB_CV_ISMEC.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
                assertEquals(MessageTag.BBB_CV_ISMEC_ANS.getId(), constraint.getError().getKey());
                ++digestMatcherValidationPerformedCounter;
            } else if (MessageTag.BBB_CV_AAMEF.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                ++allDigestMatcherFoundCounter;
            } else if (MessageTag.BBB_CV_IMEDOI.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                ++digestMatcherIntactCounter;
            } else if (MessageTag.BBB_CV_DMENMND.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                ++digestMatcherNameCounter;
            }
        }
        assertEquals(1, digestMatcherValidationPerformedCounter);
        assertEquals(0, allDigestMatcherFoundCounter);
        assertEquals(0, digestMatcherIntactCounter);
        assertEquals(0, digestMatcherNameCounter);

        checkReports(reports);
    }

    @Test
    void manifestValidationPartialStrictEntriesNotPresent() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_many_references.xml"));
        assertNotNull(diagnosticData);

        List<XmlDigestMatcher> digestMatchers = diagnosticData.getSignatures().get(0).getDigestMatchers();
        Iterator<XmlDigestMatcher> iterator = digestMatchers.iterator();
        while (iterator.hasNext()) {
            XmlDigestMatcher digestMatcher = iterator.next();
            if (DigestMatcherType.MANIFEST_ENTRY == digestMatcher.getType()) {
                iterator.remove();
            }
        }

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        BasicSignatureConstraints basicSignatureConstraints = validationPolicy.getSignatureConstraints().getBasicSignatureConstraints();

        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.FAIL);
        basicSignatureConstraints.setManifestEntryObjectExistence(levelConstraint);
        basicSignatureConstraints.setManifestEntryObjectIntact(levelConstraint);

        LevelConstraint levelWarn = new LevelConstraint();
        levelWarn.setLevel(Level.WARN);
        basicSignatureConstraints.setManifestEntryObjectGroup(levelWarn);

        basicSignatureConstraints.setManifestEntryNameMatch(levelConstraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();
        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.SIGNED_DATA_NOT_FOUND, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_CV_ISMEC_ANS)));

        DetailedReport detailedReport = reports.getDetailedReport();
        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertEquals(Indication.INDETERMINATE, signatureBBB.getConclusion().getIndication());
        assertEquals(SubIndication.SIGNED_DATA_NOT_FOUND, signatureBBB.getConclusion().getSubIndication());

        XmlCV cv = signatureBBB.getCV();
        assertNotNull(cv);
        assertEquals(Indication.INDETERMINATE, cv.getConclusion().getIndication());
        assertEquals(SubIndication.SIGNED_DATA_NOT_FOUND, cv.getConclusion().getSubIndication());

        int digestMatcherValidationPerformedCounter = 0;
        int allDigestMatcherFoundCounter = 0;
        int digestMatcherIntactCounter = 0;
        int digestMatcherNameCounter = 0;
        for (XmlConstraint constraint : cv.getConstraint()) {
            if (MessageTag.BBB_CV_ISMEC.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
                assertEquals(MessageTag.BBB_CV_ISMEC_ANS.getId(), constraint.getError().getKey());
                ++digestMatcherValidationPerformedCounter;
            } else if (MessageTag.BBB_CV_AAMEF.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                ++allDigestMatcherFoundCounter;
            } else if (MessageTag.BBB_CV_IMEDOI.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                ++digestMatcherIntactCounter;
            } else if (MessageTag.BBB_CV_DMENMND.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                ++digestMatcherNameCounter;
            }
        }
        assertEquals(1, digestMatcherValidationPerformedCounter);
        assertEquals(0, allDigestMatcherFoundCounter);
        assertEquals(0, digestMatcherIntactCounter);
        assertEquals(0, digestMatcherNameCounter);

        checkReports(reports);
    }

    @Test
    void manifestValidationPartialLaxPass() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_many_references.xml"));
        assertNotNull(diagnosticData);

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        BasicSignatureConstraints basicSignatureConstraints = validationPolicy.getSignatureConstraints().getBasicSignatureConstraints();

        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.FAIL);
        basicSignatureConstraints.setManifestEntryObjectExistence(levelConstraint);
        basicSignatureConstraints.setManifestEntryObjectIntact(levelConstraint);

        LevelConstraint levelWarn = new LevelConstraint();
        levelWarn.setLevel(Level.WARN);
        basicSignatureConstraints.setManifestEntryObjectGroup(levelWarn);
        basicSignatureConstraints.setManifestEntryNameMatch(levelWarn);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();
        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));

        DetailedReport detailedReport = reports.getDetailedReport();
        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertEquals(Indication.PASSED, signatureBBB.getConclusion().getIndication());

        XmlCV cv = signatureBBB.getCV();
        assertNotNull(cv);
        assertEquals(Indication.PASSED, cv.getConclusion().getIndication());

        int digestMatcherValidationPerformedCounter = 0;
        int allDigestMatcherFoundCounter = 0;
        int digestMatcherIntactCounter = 0;
        int digestMatcherNameCounter = 0;
        for (XmlConstraint constraint : cv.getConstraint()) {
            if (MessageTag.BBB_CV_ISMEC.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                ++digestMatcherValidationPerformedCounter;
            } else if (MessageTag.BBB_CV_AAMEF.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                ++allDigestMatcherFoundCounter;
            } else if (MessageTag.BBB_CV_IMEDOI.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                ++digestMatcherIntactCounter;
            } else if (MessageTag.BBB_CV_DMENMND.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                ++digestMatcherNameCounter;
            }
        }
        assertEquals(1, digestMatcherValidationPerformedCounter);
        assertEquals(1, allDigestMatcherFoundCounter);
        assertEquals(24, digestMatcherIntactCounter);
        assertEquals(24, digestMatcherNameCounter);

        checkReports(reports);
    }

    @Test
    void manifestValidationPartialLaxNameNoMatch() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_many_references.xml"));
        assertNotNull(diagnosticData);

        List<XmlDigestMatcher> digestMatchers = diagnosticData.getSignatures().get(0).getDigestMatchers();
        XmlDigestMatcher digestMatcher = digestMatchers.get(digestMatchers.size() - 2);
        digestMatcher.setDocumentName("wrong-name.pdf");

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        BasicSignatureConstraints basicSignatureConstraints = validationPolicy.getSignatureConstraints().getBasicSignatureConstraints();

        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.FAIL);
        basicSignatureConstraints.setManifestEntryObjectExistence(levelConstraint);
        basicSignatureConstraints.setManifestEntryObjectIntact(levelConstraint);

        LevelConstraint levelWarn = new LevelConstraint();
        levelWarn.setLevel(Level.WARN);
        basicSignatureConstraints.setManifestEntryObjectGroup(levelWarn);
        basicSignatureConstraints.setManifestEntryNameMatch(levelWarn);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();
        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationWarnings(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_CV_DMENMND_ANS)));

        DetailedReport detailedReport = reports.getDetailedReport();
        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertEquals(Indication.PASSED, signatureBBB.getConclusion().getIndication());

        XmlCV cv = signatureBBB.getCV();
        assertNotNull(cv);
        assertEquals(Indication.PASSED, cv.getConclusion().getIndication());

        int digestMatcherValidationPerformedCounter = 0;
        int allDigestMatcherFoundCounter = 0;
        int digestMatcherIntactCounter = 0;
        int digestMatcherNameValidCounter = 0;
        int digestMatcherNameInvalidCounter = 0;
        for (XmlConstraint constraint : cv.getConstraint()) {
            if (MessageTag.BBB_CV_ISMEC.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                ++digestMatcherValidationPerformedCounter;
            } else if (MessageTag.BBB_CV_AAMEF.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                ++allDigestMatcherFoundCounter;
            } else if (MessageTag.BBB_CV_IMEDOI.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                ++digestMatcherIntactCounter;
            } else if (MessageTag.BBB_CV_DMENMND.getId().equals(constraint.getName().getKey())) {
                if (XmlStatus.OK == constraint.getStatus()) {
                    ++ digestMatcherNameValidCounter;
                } else if (XmlStatus.WARNING == constraint.getStatus()) {
                    assertEquals(MessageTag.BBB_CV_DMENMND_ANS.getId(), constraint.getWarning().getKey());
                    ++digestMatcherNameInvalidCounter;
                }
            }
        }
        assertEquals(1, digestMatcherValidationPerformedCounter);
        assertEquals(1, allDigestMatcherFoundCounter);
        assertEquals(24, digestMatcherIntactCounter);
        assertEquals(23, digestMatcherNameValidCounter);
        assertEquals(1, digestMatcherNameInvalidCounter);

        checkReports(reports);
    }

    @Test
    void manifestValidationPartialLaxNoIntact() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_many_references.xml"));
        assertNotNull(diagnosticData);

        List<XmlDigestMatcher> digestMatchers = diagnosticData.getSignatures().get(0).getDigestMatchers();
        XmlDigestMatcher digestMatcher = digestMatchers.get(digestMatchers.size() - 2);
        digestMatcher.setDataIntact(false);

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        BasicSignatureConstraints basicSignatureConstraints = validationPolicy.getSignatureConstraints().getBasicSignatureConstraints();

        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.FAIL);
        basicSignatureConstraints.setManifestEntryObjectExistence(levelConstraint);
        basicSignatureConstraints.setManifestEntryObjectIntact(levelConstraint);

        LevelConstraint levelWarn = new LevelConstraint();
        levelWarn.setLevel(Level.WARN);
        basicSignatureConstraints.setManifestEntryObjectGroup(levelWarn);
        basicSignatureConstraints.setManifestEntryNameMatch(levelWarn);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();
        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_FAILED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.HASH_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_CV_IMEDOI_ANS)));

        DetailedReport detailedReport = reports.getDetailedReport();
        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertEquals(Indication.FAILED, signatureBBB.getConclusion().getIndication());
        assertEquals(SubIndication.HASH_FAILURE, signatureBBB.getConclusion().getSubIndication());

        XmlCV cv = signatureBBB.getCV();
        assertNotNull(cv);
        assertEquals(Indication.FAILED, cv.getConclusion().getIndication());
        assertEquals(SubIndication.HASH_FAILURE, cv.getConclusion().getSubIndication());

        int digestMatcherValidationPerformedCounter = 0;
        int allDigestMatcherFoundCounter = 0;
        int digestMatcherIntactValidCounter = 0;
        int digestMatcherIntactInvalidCounter = 0;
        int digestMatcherNameCounter = 0;
        for (XmlConstraint constraint : cv.getConstraint()) {
            if (MessageTag.BBB_CV_ISMEC.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                ++digestMatcherValidationPerformedCounter;
            } else if (MessageTag.BBB_CV_AAMEF.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                ++allDigestMatcherFoundCounter;
            } else if (MessageTag.BBB_CV_IMEDOI.getId().equals(constraint.getName().getKey())) {
                if (XmlStatus.OK == constraint.getStatus()) {
                    ++ digestMatcherIntactValidCounter;
                } else if (XmlStatus.NOT_OK == constraint.getStatus()) {
                    assertEquals(MessageTag.BBB_CV_IMEDOI_ANS.getId(), constraint.getError().getKey());
                    ++digestMatcherIntactInvalidCounter;
                }
            } else if (MessageTag.BBB_CV_DMENMND.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                ++digestMatcherNameCounter;
            }
        }
        assertEquals(1, digestMatcherValidationPerformedCounter);
        assertEquals(1, allDigestMatcherFoundCounter);
        assertEquals(23, digestMatcherIntactValidCounter);
        assertEquals(1, digestMatcherIntactInvalidCounter);
        assertEquals(23, digestMatcherNameCounter);

        checkReports(reports);
    }

    @Test
    void manifestValidationPartialLaxNoFound() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_many_references.xml"));
        assertNotNull(diagnosticData);

        List<XmlDigestMatcher> digestMatchers = diagnosticData.getSignatures().get(0).getDigestMatchers();
        XmlDigestMatcher digestMatcher = digestMatchers.get(digestMatchers.size() - 2);
        digestMatcher.setDataFound(false);
        digestMatcher.setDataIntact(false);

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        BasicSignatureConstraints basicSignatureConstraints = validationPolicy.getSignatureConstraints().getBasicSignatureConstraints();

        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.FAIL);
        basicSignatureConstraints.setManifestEntryObjectExistence(levelConstraint);
        basicSignatureConstraints.setManifestEntryObjectIntact(levelConstraint);

        LevelConstraint levelWarn = new LevelConstraint();
        levelWarn.setLevel(Level.WARN);
        basicSignatureConstraints.setManifestEntryObjectGroup(levelWarn);
        basicSignatureConstraints.setManifestEntryNameMatch(levelWarn);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();
        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationWarnings(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_CV_AAMEF_ANS)));

        DetailedReport detailedReport = reports.getDetailedReport();
        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertEquals(Indication.PASSED, signatureBBB.getConclusion().getIndication());

        XmlCV cv = signatureBBB.getCV();
        assertNotNull(cv);
        assertEquals(Indication.PASSED, cv.getConclusion().getIndication());

        int digestMatcherValidationPerformedCounter = 0;
        int allDigestMatcherFoundValidCounter = 0;
        int allDigestMatcherFoundInvalidCounter = 0;
        int digestMatcherIntactCounter = 0;
        int digestMatcherNameCounter = 0;
        for (XmlConstraint constraint : cv.getConstraint()) {
            if (MessageTag.BBB_CV_ISMEC.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                ++digestMatcherValidationPerformedCounter;
            } else if (MessageTag.BBB_CV_AAMEF.getId().equals(constraint.getName().getKey())) {
                if (XmlStatus.OK == constraint.getStatus()) {
                    ++ allDigestMatcherFoundValidCounter;
                } else if (XmlStatus.WARNING == constraint.getStatus()) {
                    assertEquals(MessageTag.BBB_CV_AAMEF_ANS.getId(), constraint.getWarning().getKey());
                    assertEquals(i18nProvider.getMessage(MessageTag.REFERENCES_WITH_NAMES, digestMatcher.getUri()),
                            constraint.getAdditionalInfo());
                    ++allDigestMatcherFoundInvalidCounter;
                }
            } else if (MessageTag.BBB_CV_IMEDOI.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                ++digestMatcherIntactCounter;
            } else if (MessageTag.BBB_CV_DMENMND.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                ++digestMatcherNameCounter;
            }
        }
        assertEquals(1, digestMatcherValidationPerformedCounter);
        assertEquals(0, allDigestMatcherFoundValidCounter);
        assertEquals(1, allDigestMatcherFoundInvalidCounter);
        assertEquals(23, digestMatcherIntactCounter);
        assertEquals(24, digestMatcherNameCounter);

        checkReports(reports);
    }

    @Test
    void manifestValidationPartialLaxNoFoundAll() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_many_references.xml"));
        assertNotNull(diagnosticData);

        List<XmlDigestMatcher> digestMatchers = diagnosticData.getSignatures().get(0).getDigestMatchers();
        digestMatchers = digestMatchers.stream().filter(d -> DigestMatcherType.MANIFEST_ENTRY == d.getType()).collect(Collectors.toList());
        for (XmlDigestMatcher digestMatcher : digestMatchers) {
            digestMatcher.setDocumentName(null);
            digestMatcher.setDataFound(false);
            digestMatcher.setDataIntact(false);
        }

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        BasicSignatureConstraints basicSignatureConstraints = validationPolicy.getSignatureConstraints().getBasicSignatureConstraints();

        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.FAIL);
        basicSignatureConstraints.setManifestEntryObjectExistence(levelConstraint);
        basicSignatureConstraints.setManifestEntryObjectIntact(levelConstraint);

        LevelConstraint levelWarn = new LevelConstraint();
        levelWarn.setLevel(Level.WARN);
        basicSignatureConstraints.setManifestEntryObjectGroup(levelWarn);
        basicSignatureConstraints.setManifestEntryNameMatch(levelWarn);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();
        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.SIGNED_DATA_NOT_FOUND, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_CV_ISMEC_ANS)));

        DetailedReport detailedReport = reports.getDetailedReport();
        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertEquals(Indication.INDETERMINATE, signatureBBB.getConclusion().getIndication());
        assertEquals(SubIndication.SIGNED_DATA_NOT_FOUND, signatureBBB.getConclusion().getSubIndication());

        XmlCV cv = signatureBBB.getCV();
        assertNotNull(cv);
        assertEquals(Indication.INDETERMINATE, cv.getConclusion().getIndication());
        assertEquals(SubIndication.SIGNED_DATA_NOT_FOUND, cv.getConclusion().getSubIndication());

        int digestMatcherValidationPerformedCounter = 0;
        int allDigestMatcherFoundCounter = 0;
        int digestMatcherIntactCounter = 0;
        int digestMatcherNameCounter = 0;
        for (XmlConstraint constraint : cv.getConstraint()) {
            if (MessageTag.BBB_CV_ISMEC.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
                assertEquals(MessageTag.BBB_CV_ISMEC_ANS.getId(), constraint.getError().getKey());
                ++digestMatcherValidationPerformedCounter;
            } else if (MessageTag.BBB_CV_AAMEF.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                ++allDigestMatcherFoundCounter;
            } else if (MessageTag.BBB_CV_IMEDOI.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                ++digestMatcherIntactCounter;
            } else if (MessageTag.BBB_CV_DMENMND.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                ++digestMatcherNameCounter;
            }
        }
        assertEquals(1, digestMatcherValidationPerformedCounter);
        assertEquals(0, allDigestMatcherFoundCounter);
        assertEquals(0, digestMatcherIntactCounter);
        assertEquals(0, digestMatcherNameCounter);

        checkReports(reports);
    }

    @Test
    void manifestValidationPartialLaxEntriesNotPresent() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_many_references.xml"));
        assertNotNull(diagnosticData);

        List<XmlDigestMatcher> digestMatchers = diagnosticData.getSignatures().get(0).getDigestMatchers();
        Iterator<XmlDigestMatcher> iterator = digestMatchers.iterator();
        while (iterator.hasNext()) {
            XmlDigestMatcher digestMatcher = iterator.next();
            if (DigestMatcherType.MANIFEST_ENTRY == digestMatcher.getType()) {
                iterator.remove();
            }
        }

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        BasicSignatureConstraints basicSignatureConstraints = validationPolicy.getSignatureConstraints().getBasicSignatureConstraints();

        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.FAIL);
        basicSignatureConstraints.setManifestEntryObjectExistence(levelConstraint);
        basicSignatureConstraints.setManifestEntryObjectIntact(levelConstraint);

        LevelConstraint levelWarn = new LevelConstraint();
        levelWarn.setLevel(Level.WARN);
        basicSignatureConstraints.setManifestEntryObjectGroup(levelWarn);
        basicSignatureConstraints.setManifestEntryNameMatch(levelWarn);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();
        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.SIGNED_DATA_NOT_FOUND, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_CV_ISMEC_ANS)));

        DetailedReport detailedReport = reports.getDetailedReport();
        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertEquals(Indication.INDETERMINATE, signatureBBB.getConclusion().getIndication());
        assertEquals(SubIndication.SIGNED_DATA_NOT_FOUND, signatureBBB.getConclusion().getSubIndication());

        XmlCV cv = signatureBBB.getCV();
        assertNotNull(cv);
        assertEquals(Indication.INDETERMINATE, cv.getConclusion().getIndication());
        assertEquals(SubIndication.SIGNED_DATA_NOT_FOUND, cv.getConclusion().getSubIndication());

        int digestMatcherValidationPerformedCounter = 0;
        int allDigestMatcherFoundCounter = 0;
        int digestMatcherIntactCounter = 0;
        int digestMatcherNameCounter = 0;
        for (XmlConstraint constraint : cv.getConstraint()) {
            if (MessageTag.BBB_CV_ISMEC.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
                assertEquals(MessageTag.BBB_CV_ISMEC_ANS.getId(), constraint.getError().getKey());
                ++digestMatcherValidationPerformedCounter;
            } else if (MessageTag.BBB_CV_AAMEF.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                ++allDigestMatcherFoundCounter;
            } else if (MessageTag.BBB_CV_IMEDOI.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                ++digestMatcherIntactCounter;
            } else if (MessageTag.BBB_CV_DMENMND.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                ++digestMatcherNameCounter;
            }
        }
        assertEquals(1, digestMatcherValidationPerformedCounter);
        assertEquals(0, allDigestMatcherFoundCounter);
        assertEquals(0, digestMatcherIntactCounter);
        assertEquals(0, digestMatcherNameCounter);

        checkReports(reports);
    }

    @Test
    void manifestValidationIgnoreIfNotFoundPass() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_many_references.xml"));
        assertNotNull(diagnosticData);

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        BasicSignatureConstraints basicSignatureConstraints = validationPolicy.getSignatureConstraints().getBasicSignatureConstraints();

        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.FAIL);
        basicSignatureConstraints.setManifestEntryObjectIntact(levelConstraint);

        LevelConstraint levelWarn = new LevelConstraint();
        levelWarn.setLevel(Level.WARN);
        basicSignatureConstraints.setManifestEntryObjectExistence(levelWarn);
        basicSignatureConstraints.setManifestEntryObjectGroup(levelWarn);
        basicSignatureConstraints.setManifestEntryNameMatch(levelWarn);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();
        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));

        DetailedReport detailedReport = reports.getDetailedReport();
        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertEquals(Indication.PASSED, signatureBBB.getConclusion().getIndication());

        XmlCV cv = signatureBBB.getCV();
        assertNotNull(cv);
        assertEquals(Indication.PASSED, cv.getConclusion().getIndication());

        int digestMatcherValidationPerformedCounter = 0;
        int allDigestMatcherFoundCounter = 0;
        int digestMatcherIntactCounter = 0;
        int digestMatcherNameCounter = 0;
        for (XmlConstraint constraint : cv.getConstraint()) {
            if (MessageTag.BBB_CV_ISMEC.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                ++digestMatcherValidationPerformedCounter;
            } else if (MessageTag.BBB_CV_AAMEF.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                ++allDigestMatcherFoundCounter;
            } else if (MessageTag.BBB_CV_IMEDOI.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                ++digestMatcherIntactCounter;
            } else if (MessageTag.BBB_CV_DMENMND.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                ++digestMatcherNameCounter;
            }
        }
        assertEquals(1, digestMatcherValidationPerformedCounter);
        assertEquals(1, allDigestMatcherFoundCounter);
        assertEquals(24, digestMatcherIntactCounter);
        assertEquals(24, digestMatcherNameCounter);

        checkReports(reports);
    }

    @Test
    void manifestValidationIgnoreIfNotFoundNameNoMatch() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_many_references.xml"));
        assertNotNull(diagnosticData);

        List<XmlDigestMatcher> digestMatchers = diagnosticData.getSignatures().get(0).getDigestMatchers();
        XmlDigestMatcher digestMatcher = digestMatchers.get(digestMatchers.size() - 2);
        digestMatcher.setDocumentName("wrong-name.pdf");

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        BasicSignatureConstraints basicSignatureConstraints = validationPolicy.getSignatureConstraints().getBasicSignatureConstraints();

        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.FAIL);
        basicSignatureConstraints.setManifestEntryObjectIntact(levelConstraint);

        LevelConstraint levelWarn = new LevelConstraint();
        levelWarn.setLevel(Level.WARN);
        basicSignatureConstraints.setManifestEntryObjectExistence(levelWarn);
        basicSignatureConstraints.setManifestEntryObjectGroup(levelWarn);
        basicSignatureConstraints.setManifestEntryNameMatch(levelWarn);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();
        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationWarnings(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_CV_DMENMND_ANS)));

        DetailedReport detailedReport = reports.getDetailedReport();
        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertEquals(Indication.PASSED, signatureBBB.getConclusion().getIndication());

        XmlCV cv = signatureBBB.getCV();
        assertNotNull(cv);
        assertEquals(Indication.PASSED, cv.getConclusion().getIndication());

        int digestMatcherValidationPerformedCounter = 0;
        int allDigestMatcherFoundCounter = 0;
        int digestMatcherIntactCounter = 0;
        int digestMatcherNameValidCounter = 0;
        int digestMatcherNameInvalidCounter = 0;
        for (XmlConstraint constraint : cv.getConstraint()) {
            if (MessageTag.BBB_CV_ISMEC.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                ++digestMatcherValidationPerformedCounter;
            } else if (MessageTag.BBB_CV_AAMEF.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                ++allDigestMatcherFoundCounter;
            } else if (MessageTag.BBB_CV_IMEDOI.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                ++digestMatcherIntactCounter;
            } else if (MessageTag.BBB_CV_DMENMND.getId().equals(constraint.getName().getKey())) {
                if (XmlStatus.OK == constraint.getStatus()) {
                    ++ digestMatcherNameValidCounter;
                } else if (XmlStatus.WARNING == constraint.getStatus()) {
                    assertEquals(MessageTag.BBB_CV_DMENMND_ANS.getId(), constraint.getWarning().getKey());
                    ++digestMatcherNameInvalidCounter;
                }
            }
        }
        assertEquals(1, digestMatcherValidationPerformedCounter);
        assertEquals(1, allDigestMatcherFoundCounter);
        assertEquals(24, digestMatcherIntactCounter);
        assertEquals(23, digestMatcherNameValidCounter);
        assertEquals(1, digestMatcherNameInvalidCounter);

        checkReports(reports);
    }

    @Test
    void manifestValidationIgnoreIfNotFoundNoIntact() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_many_references.xml"));
        assertNotNull(diagnosticData);

        List<XmlDigestMatcher> digestMatchers = diagnosticData.getSignatures().get(0).getDigestMatchers();
        XmlDigestMatcher digestMatcher = digestMatchers.get(digestMatchers.size() - 2);
        digestMatcher.setDataIntact(false);

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        BasicSignatureConstraints basicSignatureConstraints = validationPolicy.getSignatureConstraints().getBasicSignatureConstraints();

        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.FAIL);
        basicSignatureConstraints.setManifestEntryObjectIntact(levelConstraint);

        LevelConstraint levelWarn = new LevelConstraint();
        levelWarn.setLevel(Level.WARN);
        basicSignatureConstraints.setManifestEntryObjectExistence(levelWarn);
        basicSignatureConstraints.setManifestEntryObjectGroup(levelWarn);
        basicSignatureConstraints.setManifestEntryNameMatch(levelWarn);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();
        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_FAILED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.HASH_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_CV_IMEDOI_ANS)));

        DetailedReport detailedReport = reports.getDetailedReport();
        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertEquals(Indication.FAILED, signatureBBB.getConclusion().getIndication());
        assertEquals(SubIndication.HASH_FAILURE, signatureBBB.getConclusion().getSubIndication());

        XmlCV cv = signatureBBB.getCV();
        assertNotNull(cv);
        assertEquals(Indication.FAILED, cv.getConclusion().getIndication());
        assertEquals(SubIndication.HASH_FAILURE, cv.getConclusion().getSubIndication());

        int digestMatcherValidationPerformedCounter = 0;
        int allDigestMatcherFoundCounter = 0;
        int digestMatcherIntactValidCounter = 0;
        int digestMatcherIntactInvalidCounter = 0;
        int digestMatcherNameCounter = 0;
        for (XmlConstraint constraint : cv.getConstraint()) {
            if (MessageTag.BBB_CV_ISMEC.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                ++digestMatcherValidationPerformedCounter;
            } else if (MessageTag.BBB_CV_AAMEF.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                ++allDigestMatcherFoundCounter;
            } else if (MessageTag.BBB_CV_IMEDOI.getId().equals(constraint.getName().getKey())) {
                if (XmlStatus.OK == constraint.getStatus()) {
                    ++ digestMatcherIntactValidCounter;
                } else if (XmlStatus.NOT_OK == constraint.getStatus()) {
                    assertEquals(MessageTag.BBB_CV_IMEDOI_ANS.getId(), constraint.getError().getKey());
                    ++digestMatcherIntactInvalidCounter;
                }
            } else if (MessageTag.BBB_CV_DMENMND.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                ++digestMatcherNameCounter;
            }
        }
        assertEquals(1, digestMatcherValidationPerformedCounter);
        assertEquals(1, allDigestMatcherFoundCounter);
        assertEquals(23, digestMatcherIntactValidCounter);
        assertEquals(1, digestMatcherIntactInvalidCounter);
        assertEquals(23, digestMatcherNameCounter);

        checkReports(reports);
    }

    @Test
    void manifestValidationIgnoreIfNotFoundNoFound() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_many_references.xml"));
        assertNotNull(diagnosticData);

        List<XmlDigestMatcher> digestMatchers = diagnosticData.getSignatures().get(0).getDigestMatchers();
        XmlDigestMatcher digestMatcher = digestMatchers.get(digestMatchers.size() - 2);
        digestMatcher.setDataFound(false);
        digestMatcher.setDataIntact(false);

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        BasicSignatureConstraints basicSignatureConstraints = validationPolicy.getSignatureConstraints().getBasicSignatureConstraints();

        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.FAIL);
        basicSignatureConstraints.setManifestEntryObjectIntact(levelConstraint);

        LevelConstraint levelWarn = new LevelConstraint();
        levelWarn.setLevel(Level.WARN);
        basicSignatureConstraints.setManifestEntryObjectExistence(levelWarn);
        basicSignatureConstraints.setManifestEntryObjectGroup(levelWarn);
        basicSignatureConstraints.setManifestEntryNameMatch(levelWarn);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();
        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationWarnings(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_CV_AAMEF_ANS)));

        DetailedReport detailedReport = reports.getDetailedReport();
        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertEquals(Indication.PASSED, signatureBBB.getConclusion().getIndication());

        XmlCV cv = signatureBBB.getCV();
        assertNotNull(cv);
        assertEquals(Indication.PASSED, cv.getConclusion().getIndication());

        int digestMatcherValidationPerformedCounter = 0;
        int allDigestMatcherFoundValidCounter = 0;
        int allDigestMatcherFoundInvalidCounter = 0;
        int digestMatcherIntactCounter = 0;
        int digestMatcherNameCounter = 0;
        for (XmlConstraint constraint : cv.getConstraint()) {
            if (MessageTag.BBB_CV_ISMEC.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                ++digestMatcherValidationPerformedCounter;
            } else if (MessageTag.BBB_CV_AAMEF.getId().equals(constraint.getName().getKey())) {
                if (XmlStatus.OK == constraint.getStatus()) {
                    ++ allDigestMatcherFoundValidCounter;
                } else if (XmlStatus.WARNING == constraint.getStatus()) {
                    assertEquals(MessageTag.BBB_CV_AAMEF_ANS.getId(), constraint.getWarning().getKey());
                    assertEquals(i18nProvider.getMessage(MessageTag.REFERENCES_WITH_NAMES, digestMatcher.getUri()),
                            constraint.getAdditionalInfo());
                    ++allDigestMatcherFoundInvalidCounter;
                }
            } else if (MessageTag.BBB_CV_IMEDOI.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                ++digestMatcherIntactCounter;
            } else if (MessageTag.BBB_CV_DMENMND.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                ++digestMatcherNameCounter;
            }
        }
        assertEquals(1, digestMatcherValidationPerformedCounter);
        assertEquals(0, allDigestMatcherFoundValidCounter);
        assertEquals(1, allDigestMatcherFoundInvalidCounter);
        assertEquals(23, digestMatcherIntactCounter);
        assertEquals(24, digestMatcherNameCounter);

        checkReports(reports);
    }

    @Test
    void manifestValidationIgnoreIfNotFoundNoFoundAll() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_many_references.xml"));
        assertNotNull(diagnosticData);

        List<XmlDigestMatcher> digestMatchers = diagnosticData.getSignatures().get(0).getDigestMatchers();
        digestMatchers = digestMatchers.stream().filter(d -> DigestMatcherType.MANIFEST_ENTRY == d.getType()).collect(Collectors.toList());
        for (XmlDigestMatcher digestMatcher : digestMatchers) {
            digestMatcher.setDocumentName(null);
            digestMatcher.setDataFound(false);
            digestMatcher.setDataIntact(false);
        }

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        BasicSignatureConstraints basicSignatureConstraints = validationPolicy.getSignatureConstraints().getBasicSignatureConstraints();

        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.FAIL);
        basicSignatureConstraints.setManifestEntryObjectIntact(levelConstraint);

        LevelConstraint levelWarn = new LevelConstraint();
        levelWarn.setLevel(Level.WARN);
        basicSignatureConstraints.setManifestEntryObjectExistence(levelWarn);
        basicSignatureConstraints.setManifestEntryObjectGroup(levelWarn);
        basicSignatureConstraints.setManifestEntryNameMatch(levelWarn);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();
        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationWarnings(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_CV_ISMEC_ANS)));

        DetailedReport detailedReport = reports.getDetailedReport();
        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertEquals(Indication.PASSED, signatureBBB.getConclusion().getIndication());

        XmlCV cv = signatureBBB.getCV();
        assertNotNull(cv);
        assertEquals(Indication.PASSED, cv.getConclusion().getIndication());

        int digestMatcherValidationPerformedCounter = 0;
        int allDigestMatcherFoundCounter = 0;
        int digestMatcherIntactCounter = 0;
        int digestMatcherNameCounter = 0;
        for (XmlConstraint constraint : cv.getConstraint()) {
            if (MessageTag.BBB_CV_ISMEC.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.WARNING, constraint.getStatus());
                assertEquals(MessageTag.BBB_CV_ISMEC_ANS.getId(), constraint.getWarning().getKey());
                ++digestMatcherValidationPerformedCounter;
            } else if (MessageTag.BBB_CV_AAMEF.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.WARNING, constraint.getStatus());
                ++allDigestMatcherFoundCounter;
            } else if (MessageTag.BBB_CV_IMEDOI.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                ++digestMatcherIntactCounter;
            } else if (MessageTag.BBB_CV_DMENMND.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                ++digestMatcherNameCounter;
            }
        }
        assertEquals(1, digestMatcherValidationPerformedCounter);
        assertEquals(1, allDigestMatcherFoundCounter);
        assertEquals(0, digestMatcherIntactCounter);
        assertEquals(0, digestMatcherNameCounter);

        checkReports(reports);
    }

    @Test
    void manifestValidationIgnoreIfNotFoundEntriesNotPresent() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_many_references.xml"));
        assertNotNull(diagnosticData);

        List<XmlDigestMatcher> digestMatchers = diagnosticData.getSignatures().get(0).getDigestMatchers();
        Iterator<XmlDigestMatcher> iterator = digestMatchers.iterator();
        while (iterator.hasNext()) {
            XmlDigestMatcher digestMatcher = iterator.next();
            if (DigestMatcherType.MANIFEST_ENTRY == digestMatcher.getType()) {
                iterator.remove();
            }
        }

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        BasicSignatureConstraints basicSignatureConstraints = validationPolicy.getSignatureConstraints().getBasicSignatureConstraints();

        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.FAIL);
        basicSignatureConstraints.setManifestEntryObjectIntact(levelConstraint);

        LevelConstraint levelWarn = new LevelConstraint();
        levelWarn.setLevel(Level.WARN);
        basicSignatureConstraints.setManifestEntryObjectExistence(levelWarn);
        basicSignatureConstraints.setManifestEntryObjectGroup(levelWarn);
        basicSignatureConstraints.setManifestEntryNameMatch(levelWarn);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();
        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationWarnings(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_CV_ISMEC_ANS)));

        DetailedReport detailedReport = reports.getDetailedReport();
        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertEquals(Indication.PASSED, signatureBBB.getConclusion().getIndication());

        XmlCV cv = signatureBBB.getCV();
        assertNotNull(cv);
        assertEquals(Indication.PASSED, cv.getConclusion().getIndication());

        int digestMatcherValidationPerformedCounter = 0;
        int allDigestMatcherFoundCounter = 0;
        int digestMatcherIntactCounter = 0;
        int digestMatcherNameCounter = 0;
        for (XmlConstraint constraint : cv.getConstraint()) {
            if (MessageTag.BBB_CV_ISMEC.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.WARNING, constraint.getStatus());
                assertEquals(MessageTag.BBB_CV_ISMEC_ANS.getId(), constraint.getWarning().getKey());
                ++digestMatcherValidationPerformedCounter;
            } else if (MessageTag.BBB_CV_AAMEF.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                ++allDigestMatcherFoundCounter;
            } else if (MessageTag.BBB_CV_IMEDOI.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                ++digestMatcherIntactCounter;
            } else if (MessageTag.BBB_CV_DMENMND.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                ++digestMatcherNameCounter;
            }
        }
        assertEquals(1, digestMatcherValidationPerformedCounter);
        assertEquals(0, allDigestMatcherFoundCounter);
        assertEquals(0, digestMatcherIntactCounter);
        assertEquals(0, digestMatcherNameCounter);

        checkReports(reports);
    }

    @Test
    void manifestValidationIgnoreAllPass() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_many_references.xml"));
        assertNotNull(diagnosticData);

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        BasicSignatureConstraints basicSignatureConstraints = validationPolicy.getSignatureConstraints().getBasicSignatureConstraints();

        LevelConstraint levelWarn = new LevelConstraint();
        levelWarn.setLevel(Level.WARN);
        basicSignatureConstraints.setManifestEntryObjectIntact(levelWarn);
        basicSignatureConstraints.setManifestEntryObjectExistence(levelWarn);
        basicSignatureConstraints.setManifestEntryObjectGroup(levelWarn);
        basicSignatureConstraints.setManifestEntryNameMatch(levelWarn);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();
        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));

        DetailedReport detailedReport = reports.getDetailedReport();
        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertEquals(Indication.PASSED, signatureBBB.getConclusion().getIndication());

        XmlCV cv = signatureBBB.getCV();
        assertNotNull(cv);
        assertEquals(Indication.PASSED, cv.getConclusion().getIndication());

        int digestMatcherValidationPerformedCounter = 0;
        int allDigestMatcherFoundCounter = 0;
        int digestMatcherIntactCounter = 0;
        int digestMatcherNameCounter = 0;
        for (XmlConstraint constraint : cv.getConstraint()) {
            if (MessageTag.BBB_CV_ISMEC.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                ++digestMatcherValidationPerformedCounter;
            } else if (MessageTag.BBB_CV_AAMEF.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                ++allDigestMatcherFoundCounter;
            } else if (MessageTag.BBB_CV_IMEDOI.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                ++digestMatcherIntactCounter;
            } else if (MessageTag.BBB_CV_DMENMND.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                ++digestMatcherNameCounter;
            }
        }
        assertEquals(1, digestMatcherValidationPerformedCounter);
        assertEquals(1, allDigestMatcherFoundCounter);
        assertEquals(24, digestMatcherIntactCounter);
        assertEquals(24, digestMatcherNameCounter);

        checkReports(reports);
    }

    @Test
    void manifestValidationIgnoreAllNameNoMatch() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_many_references.xml"));
        assertNotNull(diagnosticData);

        List<XmlDigestMatcher> digestMatchers = diagnosticData.getSignatures().get(0).getDigestMatchers();
        XmlDigestMatcher digestMatcher = digestMatchers.get(digestMatchers.size() - 2);
        digestMatcher.setDocumentName("wrong-name.pdf");

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        BasicSignatureConstraints basicSignatureConstraints = validationPolicy.getSignatureConstraints().getBasicSignatureConstraints();

        LevelConstraint levelWarn = new LevelConstraint();
        levelWarn.setLevel(Level.WARN);
        basicSignatureConstraints.setManifestEntryObjectIntact(levelWarn);
        basicSignatureConstraints.setManifestEntryObjectExistence(levelWarn);
        basicSignatureConstraints.setManifestEntryObjectGroup(levelWarn);
        basicSignatureConstraints.setManifestEntryNameMatch(levelWarn);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();
        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationWarnings(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_CV_DMENMND_ANS)));

        DetailedReport detailedReport = reports.getDetailedReport();
        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertEquals(Indication.PASSED, signatureBBB.getConclusion().getIndication());

        XmlCV cv = signatureBBB.getCV();
        assertNotNull(cv);
        assertEquals(Indication.PASSED, cv.getConclusion().getIndication());

        int digestMatcherValidationPerformedCounter = 0;
        int allDigestMatcherFoundCounter = 0;
        int digestMatcherIntactCounter = 0;
        int digestMatcherNameValidCounter = 0;
        int digestMatcherNameInvalidCounter = 0;
        for (XmlConstraint constraint : cv.getConstraint()) {
            if (MessageTag.BBB_CV_ISMEC.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                ++digestMatcherValidationPerformedCounter;
            } else if (MessageTag.BBB_CV_AAMEF.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                ++allDigestMatcherFoundCounter;
            } else if (MessageTag.BBB_CV_IMEDOI.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                ++digestMatcherIntactCounter;
            } else if (MessageTag.BBB_CV_DMENMND.getId().equals(constraint.getName().getKey())) {
                if (XmlStatus.OK == constraint.getStatus()) {
                    ++ digestMatcherNameValidCounter;
                } else if (XmlStatus.WARNING == constraint.getStatus()) {
                    assertEquals(MessageTag.BBB_CV_DMENMND_ANS.getId(), constraint.getWarning().getKey());
                    ++digestMatcherNameInvalidCounter;
                }
            }
        }
        assertEquals(1, digestMatcherValidationPerformedCounter);
        assertEquals(1, allDigestMatcherFoundCounter);
        assertEquals(24, digestMatcherIntactCounter);
        assertEquals(23, digestMatcherNameValidCounter);
        assertEquals(1, digestMatcherNameInvalidCounter);

        checkReports(reports);
    }

    @Test
    void manifestValidationIgnoreAllNoIntact() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_many_references.xml"));
        assertNotNull(diagnosticData);

        List<XmlDigestMatcher> digestMatchers = diagnosticData.getSignatures().get(0).getDigestMatchers();
        XmlDigestMatcher digestMatcher = digestMatchers.get(digestMatchers.size() - 2);
        digestMatcher.setDataIntact(false);

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        BasicSignatureConstraints basicSignatureConstraints = validationPolicy.getSignatureConstraints().getBasicSignatureConstraints();

        LevelConstraint levelWarn = new LevelConstraint();
        levelWarn.setLevel(Level.WARN);
        basicSignatureConstraints.setManifestEntryObjectIntact(levelWarn);
        basicSignatureConstraints.setManifestEntryObjectExistence(levelWarn);
        basicSignatureConstraints.setManifestEntryObjectGroup(levelWarn);
        basicSignatureConstraints.setManifestEntryNameMatch(levelWarn);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();
        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationWarnings(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_CV_IMEDOI_ANS)));

        DetailedReport detailedReport = reports.getDetailedReport();
        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertEquals(Indication.PASSED, signatureBBB.getConclusion().getIndication());

        XmlCV cv = signatureBBB.getCV();
        assertNotNull(cv);
        assertEquals(Indication.PASSED, cv.getConclusion().getIndication());

        int digestMatcherValidationPerformedCounter = 0;
        int allDigestMatcherFoundCounter = 0;
        int digestMatcherIntactValidCounter = 0;
        int digestMatcherIntactInvalidCounter = 0;
        int digestMatcherNameCounter = 0;
        for (XmlConstraint constraint : cv.getConstraint()) {
            if (MessageTag.BBB_CV_ISMEC.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                ++digestMatcherValidationPerformedCounter;
            } else if (MessageTag.BBB_CV_AAMEF.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                ++allDigestMatcherFoundCounter;
            } else if (MessageTag.BBB_CV_IMEDOI.getId().equals(constraint.getName().getKey())) {
                if (XmlStatus.OK == constraint.getStatus()) {
                    ++ digestMatcherIntactValidCounter;
                } else if (XmlStatus.WARNING == constraint.getStatus()) {
                    assertEquals(MessageTag.BBB_CV_IMEDOI_ANS.getId(), constraint.getWarning().getKey());
                    ++digestMatcherIntactInvalidCounter;
                }
            } else if (MessageTag.BBB_CV_DMENMND.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                ++digestMatcherNameCounter;
            }
        }
        assertEquals(1, digestMatcherValidationPerformedCounter);
        assertEquals(1, allDigestMatcherFoundCounter);
        assertEquals(23, digestMatcherIntactValidCounter);
        assertEquals(1, digestMatcherIntactInvalidCounter);
        assertEquals(24, digestMatcherNameCounter);

        checkReports(reports);
    }

    @Test
    void manifestValidationIgnoreAllNoFound() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_many_references.xml"));
        assertNotNull(diagnosticData);

        List<XmlDigestMatcher> digestMatchers = diagnosticData.getSignatures().get(0).getDigestMatchers();
        XmlDigestMatcher digestMatcher = digestMatchers.get(digestMatchers.size() - 2);
        digestMatcher.setDataFound(false);
        digestMatcher.setDataIntact(false);

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        BasicSignatureConstraints basicSignatureConstraints = validationPolicy.getSignatureConstraints().getBasicSignatureConstraints();

        LevelConstraint levelWarn = new LevelConstraint();
        levelWarn.setLevel(Level.WARN);
        basicSignatureConstraints.setManifestEntryObjectIntact(levelWarn);
        basicSignatureConstraints.setManifestEntryObjectExistence(levelWarn);
        basicSignatureConstraints.setManifestEntryObjectGroup(levelWarn);
        basicSignatureConstraints.setManifestEntryNameMatch(levelWarn);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();
        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationWarnings(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_CV_AAMEF_ANS)));

        DetailedReport detailedReport = reports.getDetailedReport();
        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertEquals(Indication.PASSED, signatureBBB.getConclusion().getIndication());

        XmlCV cv = signatureBBB.getCV();
        assertNotNull(cv);
        assertEquals(Indication.PASSED, cv.getConclusion().getIndication());

        int digestMatcherValidationPerformedCounter = 0;
        int allDigestMatcherFoundValidCounter = 0;
        int allDigestMatcherFoundInvalidCounter = 0;
        int digestMatcherIntactCounter = 0;
        int digestMatcherNameCounter = 0;
        for (XmlConstraint constraint : cv.getConstraint()) {
            if (MessageTag.BBB_CV_ISMEC.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                ++digestMatcherValidationPerformedCounter;
            } else if (MessageTag.BBB_CV_AAMEF.getId().equals(constraint.getName().getKey())) {
                if (XmlStatus.OK == constraint.getStatus()) {
                    ++ allDigestMatcherFoundValidCounter;
                } else if (XmlStatus.WARNING == constraint.getStatus()) {
                    assertEquals(MessageTag.BBB_CV_AAMEF_ANS.getId(), constraint.getWarning().getKey());
                    assertEquals(i18nProvider.getMessage(MessageTag.REFERENCES_WITH_NAMES, digestMatcher.getUri()),
                            constraint.getAdditionalInfo());
                    ++allDigestMatcherFoundInvalidCounter;
                }
            } else if (MessageTag.BBB_CV_IMEDOI.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                ++digestMatcherIntactCounter;
            } else if (MessageTag.BBB_CV_DMENMND.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                ++digestMatcherNameCounter;
            }
        }
        assertEquals(1, digestMatcherValidationPerformedCounter);
        assertEquals(0, allDigestMatcherFoundValidCounter);
        assertEquals(1, allDigestMatcherFoundInvalidCounter);
        assertEquals(23, digestMatcherIntactCounter);
        assertEquals(24, digestMatcherNameCounter);

        checkReports(reports);
    }

    @Test
    void manifestValidationIgnoreAllNotFoundAll() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_many_references.xml"));
        assertNotNull(diagnosticData);

        List<XmlDigestMatcher> digestMatchers = diagnosticData.getSignatures().get(0).getDigestMatchers();
        digestMatchers = digestMatchers.stream().filter(d -> DigestMatcherType.MANIFEST_ENTRY == d.getType()).collect(Collectors.toList());
        for (XmlDigestMatcher digestMatcher : digestMatchers) {
            digestMatcher.setDocumentName(null);
            digestMatcher.setDataFound(false);
            digestMatcher.setDataIntact(false);
        }

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        BasicSignatureConstraints basicSignatureConstraints = validationPolicy.getSignatureConstraints().getBasicSignatureConstraints();

        LevelConstraint levelWarn = new LevelConstraint();
        levelWarn.setLevel(Level.WARN);
        basicSignatureConstraints.setManifestEntryObjectIntact(levelWarn);
        basicSignatureConstraints.setManifestEntryObjectExistence(levelWarn);
        basicSignatureConstraints.setManifestEntryObjectGroup(levelWarn);
        basicSignatureConstraints.setManifestEntryNameMatch(levelWarn);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();
        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationWarnings(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_CV_ISMEC_ANS)));

        DetailedReport detailedReport = reports.getDetailedReport();
        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertEquals(Indication.PASSED, signatureBBB.getConclusion().getIndication());

        XmlCV cv = signatureBBB.getCV();
        assertNotNull(cv);
        assertEquals(Indication.PASSED, cv.getConclusion().getIndication());

        int digestMatcherValidationPerformedCounter = 0;
        int allDigestMatcherFoundCounter = 0;
        int digestMatcherIntactCounter = 0;
        int digestMatcherNameCounter = 0;
        for (XmlConstraint constraint : cv.getConstraint()) {
            if (MessageTag.BBB_CV_ISMEC.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.WARNING, constraint.getStatus());
                assertEquals(MessageTag.BBB_CV_ISMEC_ANS.getId(), constraint.getWarning().getKey());
                ++digestMatcherValidationPerformedCounter;
            } else if (MessageTag.BBB_CV_AAMEF.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.WARNING, constraint.getStatus());
                ++allDigestMatcherFoundCounter;
            } else if (MessageTag.BBB_CV_IMEDOI.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                ++digestMatcherIntactCounter;
            } else if (MessageTag.BBB_CV_DMENMND.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                ++digestMatcherNameCounter;
            }
        }
        assertEquals(1, digestMatcherValidationPerformedCounter);
        assertEquals(1, allDigestMatcherFoundCounter);
        assertEquals(0, digestMatcherIntactCounter);
        assertEquals(0, digestMatcherNameCounter);

        checkReports(reports);
    }

    @Test
    void manifestValidationIgnoreAllEntriesNotPresent() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_many_references.xml"));
        assertNotNull(diagnosticData);

        List<XmlDigestMatcher> digestMatchers = diagnosticData.getSignatures().get(0).getDigestMatchers();
        Iterator<XmlDigestMatcher> iterator = digestMatchers.iterator();
        while (iterator.hasNext()) {
            XmlDigestMatcher digestMatcher = iterator.next();
            if (DigestMatcherType.MANIFEST_ENTRY == digestMatcher.getType()) {
                iterator.remove();
            }
        }

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        BasicSignatureConstraints basicSignatureConstraints = validationPolicy.getSignatureConstraints().getBasicSignatureConstraints();

        LevelConstraint levelWarn = new LevelConstraint();
        levelWarn.setLevel(Level.WARN);
        basicSignatureConstraints.setManifestEntryObjectIntact(levelWarn);
        basicSignatureConstraints.setManifestEntryObjectExistence(levelWarn);
        basicSignatureConstraints.setManifestEntryObjectGroup(levelWarn);
        basicSignatureConstraints.setManifestEntryNameMatch(levelWarn);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();
        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationWarnings(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_CV_ISMEC_ANS)));

        DetailedReport detailedReport = reports.getDetailedReport();
        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertEquals(Indication.PASSED, signatureBBB.getConclusion().getIndication());

        XmlCV cv = signatureBBB.getCV();
        assertNotNull(cv);
        assertEquals(Indication.PASSED, cv.getConclusion().getIndication());

        int digestMatcherValidationPerformedCounter = 0;
        int allDigestMatcherFoundCounter = 0;
        int digestMatcherIntactCounter = 0;
        int digestMatcherNameCounter = 0;
        for (XmlConstraint constraint : cv.getConstraint()) {
            if (MessageTag.BBB_CV_ISMEC.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.WARNING, constraint.getStatus());
                assertEquals(MessageTag.BBB_CV_ISMEC_ANS.getId(), constraint.getWarning().getKey());
                ++digestMatcherValidationPerformedCounter;
            } else if (MessageTag.BBB_CV_AAMEF.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                ++allDigestMatcherFoundCounter;
            } else if (MessageTag.BBB_CV_IMEDOI.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                ++digestMatcherIntactCounter;
            } else if (MessageTag.BBB_CV_DMENMND.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                ++digestMatcherNameCounter;
            }
        }
        assertEquals(1, digestMatcherValidationPerformedCounter);
        assertEquals(0, allDigestMatcherFoundCounter);
        assertEquals(0, digestMatcherIntactCounter);
        assertEquals(0, digestMatcherNameCounter);

        checkReports(reports);
    }

}
