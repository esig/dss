package eu.europa.esig.dss.validation.executor.process;

import eu.europa.esig.dss.detailedreport.DetailedReport;
import eu.europa.esig.dss.detailedreport.jaxb.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlPSV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessArchivalData;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessArchivalDataTimestamp;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessBasicTimestamp;
import eu.europa.esig.dss.diagnostic.DiagnosticDataFacade;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTimestamp;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.ValidationPolicy;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.validation.executor.signature.DefaultSignatureProcessExecutor;
import eu.europa.esig.dss.validation.reports.Reports;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.util.Calendar;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DSS2972ExecutorTest extends AbstractProcessExecutorTest {

    @Test
    void expiredSigAndTstTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/dss-2070.xml"));
        assertNotNull(xmlDiagnosticData);

        Calendar calendar = Calendar.getInstance();
        calendar.set(Calendar.YEAR, 2022);
        xmlDiagnosticData.setValidationDate(calendar.getTime());

        ValidationPolicy validationPolicy = loadDefaultPolicy();

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.OUT_OF_BOUNDS_NO_POE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_XCV_ICTIVRSC_ANS)));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.LTV_ISCKNR_ANS1)));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.ARCH_LTAIVMP_ANS)));
        assertFalse(checkMessageValuePresence(simpleReport.getAdESValidationWarnings(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.PSV_IPTVC_ANS)));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.INDETERMINATE, detailedReport.getBasicValidationIndication(detailedReport.getFirstSignatureId()));
        assertEquals(SubIndication.OUT_OF_BOUNDS_NO_POE, detailedReport.getBasicValidationSubIndication(detailedReport.getFirstSignatureId()));

        eu.europa.esig.dss.detailedreport.jaxb.XmlTimestamp xmlTimestamp = detailedReport.getXmlTimestampById(xmlDiagnosticData.getUsedTimestamps().get(0).getId());
        XmlValidationProcessBasicTimestamp basicValidationProcessTimestamp = xmlTimestamp.getValidationProcessBasicTimestamp();
        assertEquals(Indication.INDETERMINATE, basicValidationProcessTimestamp.getConclusion().getIndication());
        assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, basicValidationProcessTimestamp.getConclusion().getSubIndication());

        XmlValidationProcessArchivalDataTimestamp validationProcessArchivalDataTimestamp = xmlTimestamp.getValidationProcessArchivalDataTimestamp();
        assertEquals(Indication.INDETERMINATE, validationProcessArchivalDataTimestamp.getConclusion().getIndication());
        assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, validationProcessArchivalDataTimestamp.getConclusion().getSubIndication());

        boolean basicTstAllowedValidationFound = false;
        boolean basicValidationCheckFound = false;
        boolean tstPSVFound = false;
        for (XmlConstraint xmlConstraint : validationProcessArchivalDataTimestamp.getConstraint()) {
            if (MessageTag.ARCH_IRTVBBA.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                basicTstAllowedValidationFound = true;

            } else if (MessageTag.ADEST_IBSVPTC.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.WARNING, xmlConstraint.getStatus());
                assertEquals(MessageTag.ADEST_IBSVPTC_ANS.getId(), xmlConstraint.getWarning().getKey());
                basicValidationCheckFound = true;

            } else if (MessageTag.PSV_IPTVC.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                assertEquals(MessageTag.PSV_IPTVC_ANS.getId(), xmlConstraint.getError().getKey());
                tstPSVFound = true;

            } else {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
            }
        }
        assertTrue(basicTstAllowedValidationFound);
        assertTrue(basicValidationCheckFound);
        assertTrue(tstPSVFound);

        XmlBasicBuildingBlocks tstBBB = detailedReport.getBasicBuildingBlockById(xmlDiagnosticData.getUsedTimestamps().get(0).getId());
        assertNotNull(tstBBB);

        XmlPSV psv = tstBBB.getPSV();
        assertEquals(Indication.INDETERMINATE, psv.getConclusion().getIndication());
        assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, psv.getConclusion().getSubIndication());

        XmlValidationProcessArchivalData validationProcessArchivalData = detailedReport.getXmlSignatureById(detailedReport.getFirstSignatureId()).getValidationProcessArchivalData();
        assertEquals(Indication.INDETERMINATE, validationProcessArchivalData.getConclusion().getIndication());
        assertEquals(SubIndication.OUT_OF_BOUNDS_NO_POE, validationProcessArchivalData.getConclusion().getSubIndication());

        boolean tstAllowedValidationFound = false;
        boolean ltvMaterialPresentCheckFound = false;
        for (XmlConstraint xmlConstraint : validationProcessArchivalData.getConstraint()) {
            if (MessageTag.ADEST_IBSVPTADC.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.WARNING, xmlConstraint.getStatus());
                assertEquals(MessageTag.ADEST_IBSVPTADC_ANS.getId(), xmlConstraint.getWarning().getKey());
                tstAllowedValidationFound = true;

            } else if (MessageTag.ARCH_LTAIVMP.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                assertEquals(MessageTag.ARCH_LTAIVMP_ANS.getId(), xmlConstraint.getError().getKey());
                ltvMaterialPresentCheckFound = true;

            } else {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
            }
        }
        assertFalse(tstAllowedValidationFound);
        assertTrue(ltvMaterialPresentCheckFound);
    }

    @Test
    void expiredSigAndTstWithTstCheckWarnLevelTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/dss-2070.xml"));
        assertNotNull(xmlDiagnosticData);

        Calendar calendar = Calendar.getInstance();
        calendar.set(Calendar.YEAR, 2022);
        xmlDiagnosticData.setValidationDate(calendar.getTime());

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.WARN);
        validationPolicy.getTimestampConstraints().setTimestampValid(constraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.OUT_OF_BOUNDS_NO_POE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_XCV_ICTIVRSC_ANS)));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.ARCH_LTAIVMP_ANS)));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.INDETERMINATE, detailedReport.getBasicValidationIndication(detailedReport.getFirstSignatureId()));
        assertEquals(SubIndication.OUT_OF_BOUNDS_NO_POE, detailedReport.getBasicValidationSubIndication(detailedReport.getFirstSignatureId()));

        XmlValidationProcessBasicTimestamp validationProcessTimestamp = detailedReport.getXmlTimestampById(
                xmlDiagnosticData.getUsedTimestamps().get(0).getId()).getValidationProcessBasicTimestamp();
        assertEquals(Indication.INDETERMINATE, validationProcessTimestamp.getConclusion().getIndication());
        assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, validationProcessTimestamp.getConclusion().getSubIndication());

        XmlBasicBuildingBlocks tstBBB = detailedReport.getBasicBuildingBlockById(xmlDiagnosticData.getUsedTimestamps().get(0).getId());
        assertNotNull(tstBBB);

        XmlPSV psv = tstBBB.getPSV();
        assertEquals(Indication.INDETERMINATE, psv.getConclusion().getIndication());
        assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, psv.getConclusion().getSubIndication());

        eu.europa.esig.dss.detailedreport.jaxb.XmlSignature xmlSignature = detailedReport.getXmlSignatureById(detailedReport.getFirstSignatureId());
        XmlValidationProcessArchivalData validationProcessArchivalData = xmlSignature.getValidationProcessArchivalData();
        assertEquals(Indication.INDETERMINATE, validationProcessArchivalData.getConclusion().getIndication());
        assertEquals(SubIndication.OUT_OF_BOUNDS_NO_POE, validationProcessArchivalData.getConclusion().getSubIndication());

        boolean valMaterialPresentCheckFound = false;
        boolean tstAllowedValidationFound = false;
        boolean sigPSVFound = false;
        for (XmlConstraint xmlConstraint : validationProcessArchivalData.getConstraint()) {
            if (MessageTag.ADEST_IBSVPTADC.getId().equals(xmlConstraint.getName().getKey())) {
                tstAllowedValidationFound = true;

            } else if (MessageTag.ARCH_LTAIVMP.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                assertEquals(MessageTag.ARCH_LTAIVMP_ANS.getId(), xmlConstraint.getError().getKey());
                valMaterialPresentCheckFound = true;

            } else if (MessageTag.PSV_IPSVC.getId().equals(xmlConstraint.getName().getKey())) {
                sigPSVFound = true;

            } else {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
            }
        }
        assertTrue(valMaterialPresentCheckFound);
        assertFalse(tstAllowedValidationFound);
        assertFalse(sigPSVFound);

        XmlValidationProcessArchivalDataTimestamp tstValidationProcessArchivalData = xmlSignature.getTimestamps().get(0).getValidationProcessArchivalDataTimestamp();
        assertEquals(Indication.INDETERMINATE, tstValidationProcessArchivalData.getConclusion().getIndication());
        assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, tstValidationProcessArchivalData.getConclusion().getSubIndication());

        boolean tstAllowedBasicValidationFound = false;
        boolean tstConclusiveBasicValidationFound = false;
        boolean tstPSVFound = false;

        List<XmlConstraint> constraints = tstValidationProcessArchivalData.getConstraint();
        for (XmlConstraint xmlConstraint : constraints) {
            if (MessageTag.ARCH_IRTVBBA.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                tstAllowedBasicValidationFound = true;

            } else if (MessageTag.ADEST_IBSVPTC.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.WARNING, xmlConstraint.getStatus());
                assertEquals(MessageTag.ADEST_IBSVPTC_ANS.getId(), xmlConstraint.getWarning().getKey());
                tstConclusiveBasicValidationFound = true;

            } else if (MessageTag.PSV_IPTVC.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                assertEquals(MessageTag.PSV_IPTVC_ANS.getId(), xmlConstraint.getError().getKey());
                tstPSVFound = true;

            } else {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
            }
        }

        assertTrue(tstAllowedBasicValidationFound);
        assertTrue(tstConclusiveBasicValidationFound);
        assertTrue(tstPSVFound);
    }

    @Test
    void sigWithFailedTstFailLevelTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/valid-diag-data-lta.xml"));
        assertNotNull(xmlDiagnosticData);

        xmlDiagnosticData.getUsedTimestamps().get(0).getBasicSignature().setSignatureIntact(false);

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);
        validationPolicy.getTimestampConstraints().setTimestampValid(constraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_FAILED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.SIG_CRYPTO_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
        assertFalse(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.PSV_IPSVC_ANS)));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.ADEST_IBSVPTADC_ANS)));
        assertFalse(checkMessageValuePresence(simpleReport.getAdESValidationWarnings(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.PSV_IPTVC_ANS)));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.PASSED, detailedReport.getBasicValidationIndication(detailedReport.getFirstSignatureId()));

        XmlValidationProcessBasicTimestamp validationProcessTimestamp = detailedReport.getXmlTimestampById(
                xmlDiagnosticData.getUsedTimestamps().get(0).getId()).getValidationProcessBasicTimestamp();
        assertEquals(Indication.FAILED, validationProcessTimestamp.getConclusion().getIndication());
        assertEquals(SubIndication.SIG_CRYPTO_FAILURE, validationProcessTimestamp.getConclusion().getSubIndication());

        XmlBasicBuildingBlocks tstBBB = detailedReport.getBasicBuildingBlockById(xmlDiagnosticData.getUsedTimestamps().get(0).getId());
        assertNotNull(tstBBB);

        XmlPSV psv = tstBBB.getPSV();
        assertNull(psv);

        XmlValidationProcessArchivalData validationProcessArchivalData = detailedReport.getXmlSignatureById(detailedReport.getFirstSignatureId()).getValidationProcessArchivalData();
        assertEquals(Indication.FAILED, validationProcessArchivalData.getConclusion().getIndication());
        assertEquals(SubIndication.SIG_CRYPTO_FAILURE, validationProcessArchivalData.getConclusion().getSubIndication());

        boolean tstAllowedValidationFound = false;
        for (XmlConstraint xmlConstraint : validationProcessArchivalData.getConstraint()) {
            if (MessageTag.ADEST_IBSVPTADC.getId().equals(xmlConstraint.getName().getKey())) {
                if (XmlStatus.NOT_OK == xmlConstraint.getStatus()) {
                    assertEquals(MessageTag.ADEST_IBSVPTADC_ANS.getId(), xmlConstraint.getError().getKey());
                    tstAllowedValidationFound = true;
                }
            } else {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
            }
        }
        assertTrue(tstAllowedValidationFound);
    }

    @Test
    void tLevelTstFoundValidTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/valid-diag-data-lta.xml"));
        assertNotNull(xmlDiagnosticData);

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);
        validationPolicy.getSignatureConstraints().getUnsignedAttributes().setTLevelTimeStamp(constraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertFalse(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_SAV_IVTTSTP_ANS)));
        assertFalse(checkMessageValuePresence(simpleReport.getAdESValidationWarnings(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.ARCH_IRTVBBA_ANS)));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.PASSED, detailedReport.getBasicValidationIndication(detailedReport.getFirstSignatureId()));

        for (XmlTimestamp xmlTimestamp : xmlDiagnosticData.getUsedTimestamps()) {
            XmlValidationProcessBasicTimestamp validationProcessTimestamp = detailedReport.getXmlTimestampById(xmlTimestamp.getId()).getValidationProcessBasicTimestamp();
            assertEquals(Indication.PASSED, validationProcessTimestamp.getConclusion().getIndication());
        }

        XmlValidationProcessArchivalData validationProcessArchivalData = detailedReport.getXmlSignatureById(detailedReport.getFirstSignatureId()).getValidationProcessArchivalData();
        assertEquals(Indication.PASSED, validationProcessArchivalData.getConclusion().getIndication());

        boolean tLevelCheckFound = false;
        for (XmlConstraint xmlConstraint : validationProcessArchivalData.getConstraint()) {
            if (MessageTag.BBB_SAV_IVTTSTP.getId().equals(xmlConstraint.getName().getKey())) {
                tLevelCheckFound = true;
            }
            assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
        }
        assertTrue(tLevelCheckFound);
    }

    @Test
    void tLevelTstFoundInvalidTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/valid-diag-data-lta.xml"));
        assertNotNull(xmlDiagnosticData);

        xmlDiagnosticData.getUsedTimestamps().get(0).getBasicSignature().setSignatureIntact(false);

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);
        validationPolicy.getSignatureConstraints().getUnsignedAttributes().setTLevelTimeStamp(constraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_SAV_IVTTSTP_ANS)));
        assertFalse(checkMessageValuePresence(simpleReport.getAdESValidationWarnings(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.ARCH_IRTVBBA_ANS)));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.PASSED, detailedReport.getBasicValidationIndication(detailedReport.getFirstSignatureId()));

        boolean validTstFound = false;
        boolean invalidTstFound = false;
        for (XmlTimestamp xmlTimestamp : xmlDiagnosticData.getUsedTimestamps()) {
            XmlValidationProcessBasicTimestamp validationProcessTimestamp = detailedReport.getXmlTimestampById(xmlTimestamp.getId()).getValidationProcessBasicTimestamp();
            if (Indication.PASSED == validationProcessTimestamp.getConclusion().getIndication()) {
                assertEquals(TimestampType.ARCHIVE_TIMESTAMP, xmlTimestamp.getType());
                validTstFound = true;
            } else if (Indication.FAILED == validationProcessTimestamp.getConclusion().getIndication()) {
                assertEquals(SubIndication.SIG_CRYPTO_FAILURE, validationProcessTimestamp.getConclusion().getSubIndication());
                assertEquals(TimestampType.SIGNATURE_TIMESTAMP, xmlTimestamp.getType());
                invalidTstFound = true;
            }
        }
        assertTrue(validTstFound);
        assertTrue(invalidTstFound);

        XmlValidationProcessArchivalData validationProcessArchivalData = detailedReport.getXmlSignatureById(detailedReport.getFirstSignatureId()).getValidationProcessArchivalData();
        assertEquals(Indication.INDETERMINATE, validationProcessArchivalData.getConclusion().getIndication());
        assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, validationProcessArchivalData.getConclusion().getSubIndication());

        boolean tstValidationCheckSuccessFound = false;
        boolean tstValidationCheckFailureFound = false;
        boolean tLevelCheckFound = false;
        for (XmlConstraint xmlConstraint : validationProcessArchivalData.getConstraint()) {
            if (MessageTag.BBB_SAV_IVTTSTP.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                assertEquals(MessageTag.BBB_SAV_IVTTSTP_ANS.getId(), xmlConstraint.getError().getKey());
                tLevelCheckFound = true;

            } else if (MessageTag.ADEST_IBSVPTADC.getId().equals(xmlConstraint.getName().getKey())) {
                if (XmlStatus.OK.equals(xmlConstraint.getStatus())) {
                    tstValidationCheckSuccessFound = true;
                } else if (XmlStatus.WARNING.equals(xmlConstraint.getStatus())) {
                    assertEquals(MessageTag.ADEST_IBSVPTADC_ANS.getId(), xmlConstraint.getWarning().getKey());
                    tstValidationCheckFailureFound = true;
                }

            } else {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
            }

        }
        assertTrue(tstValidationCheckSuccessFound);
        assertTrue(tstValidationCheckFailureFound);
        assertTrue(tLevelCheckFound);
    }

    @Test
    void ltaLevelTstFoundValidTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/valid-diag-data-lta.xml"));
        assertNotNull(xmlDiagnosticData);

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);
        validationPolicy.getSignatureConstraints().getUnsignedAttributes().setLTALevelTimeStamp(constraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertFalse(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_SAV_IVLTATSTP_ANS)));
        assertFalse(checkMessageValuePresence(simpleReport.getAdESValidationWarnings(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.ARCH_IRTVBBA_ANS)));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.PASSED, detailedReport.getBasicValidationIndication(detailedReport.getFirstSignatureId()));

        for (XmlTimestamp xmlTimestamp : xmlDiagnosticData.getUsedTimestamps()) {
            XmlValidationProcessBasicTimestamp validationProcessTimestamp = detailedReport.getXmlTimestampById(xmlTimestamp.getId()).getValidationProcessBasicTimestamp();
            assertEquals(Indication.PASSED, validationProcessTimestamp.getConclusion().getIndication());
        }

        XmlValidationProcessArchivalData validationProcessArchivalData = detailedReport.getXmlSignatureById(detailedReport.getFirstSignatureId()).getValidationProcessArchivalData();
        assertEquals(Indication.PASSED, validationProcessArchivalData.getConclusion().getIndication());

        boolean ltaLevelCheckFound = false;
        for (XmlConstraint xmlConstraint : validationProcessArchivalData.getConstraint()) {
            if (MessageTag.BBB_SAV_IVLTATSTP.getId().equals(xmlConstraint.getName().getKey())) {
                ltaLevelCheckFound = true;
            }
            assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
        }
        assertTrue(ltaLevelCheckFound);
    }

    @Test
    void ltaLevelTstFoundInvalidTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/valid-diag-data-lta.xml"));
        assertNotNull(xmlDiagnosticData);

        xmlDiagnosticData.getUsedTimestamps().get(1).getBasicSignature().setSignatureIntact(false);

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);
        validationPolicy.getSignatureConstraints().getUnsignedAttributes().setLTALevelTimeStamp(constraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_SAV_IVLTATSTP_ANS)));
        assertFalse(checkMessageValuePresence(simpleReport.getAdESValidationWarnings(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.ARCH_IRTVBBA_ANS)));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.PASSED, detailedReport.getBasicValidationIndication(detailedReport.getFirstSignatureId()));

        boolean validTstFound = false;
        boolean invalidTstFound = false;
        for (XmlTimestamp xmlTimestamp : xmlDiagnosticData.getUsedTimestamps()) {
            XmlValidationProcessBasicTimestamp validationProcessTimestamp = detailedReport.getXmlTimestampById(xmlTimestamp.getId()).getValidationProcessBasicTimestamp();
            if (Indication.PASSED == validationProcessTimestamp.getConclusion().getIndication()) {
                assertEquals(TimestampType.SIGNATURE_TIMESTAMP, xmlTimestamp.getType());
                validTstFound = true;
            } else if (Indication.FAILED == validationProcessTimestamp.getConclusion().getIndication()) {
                assertEquals(SubIndication.SIG_CRYPTO_FAILURE, validationProcessTimestamp.getConclusion().getSubIndication());
                assertEquals(TimestampType.ARCHIVE_TIMESTAMP, xmlTimestamp.getType());
                invalidTstFound = true;
            }
        }
        assertTrue(validTstFound);
        assertTrue(invalidTstFound);

        XmlValidationProcessArchivalData validationProcessArchivalData = detailedReport.getXmlSignatureById(detailedReport.getFirstSignatureId()).getValidationProcessArchivalData();
        assertEquals(Indication.INDETERMINATE, validationProcessArchivalData.getConclusion().getIndication());
        assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, validationProcessArchivalData.getConclusion().getSubIndication());

        boolean tstValidationCheckSuccessFound = false;
        boolean tstValidationCheckFailureFound = false;
        boolean ltaLevelCheckFound = false;
        for (XmlConstraint xmlConstraint : validationProcessArchivalData.getConstraint()) {
            if (MessageTag.BBB_SAV_IVLTATSTP.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                assertEquals(MessageTag.BBB_SAV_IVLTATSTP_ANS.getId(), xmlConstraint.getError().getKey());
                ltaLevelCheckFound = true;

            } else if (MessageTag.ADEST_IBSVPTADC.getId().equals(xmlConstraint.getName().getKey())) {
                if (XmlStatus.OK.equals(xmlConstraint.getStatus())) {
                    tstValidationCheckSuccessFound = true;
                } else if (XmlStatus.WARNING.equals(xmlConstraint.getStatus())) {
                    assertEquals(MessageTag.ADEST_IBSVPTADC_ANS.getId(), xmlConstraint.getWarning().getKey());
                    tstValidationCheckFailureFound = true;
                }

            } else {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
            }

        }
        assertTrue(tstValidationCheckSuccessFound);
        assertTrue(tstValidationCheckFailureFound);
        assertTrue(ltaLevelCheckFound);
    }

}
