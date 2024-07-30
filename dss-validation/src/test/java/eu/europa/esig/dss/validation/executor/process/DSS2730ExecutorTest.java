package eu.europa.esig.dss.validation.executor.process;

import eu.europa.esig.dss.detailedreport.DetailedReport;
import eu.europa.esig.dss.detailedreport.jaxb.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlPSV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSubXCV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessArchivalData;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessArchivalDataTimestamp;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessBasicSignature;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessBasicTimestamp;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessLongTermData;
import eu.europa.esig.dss.detailedreport.jaxb.XmlXCV;
import eu.europa.esig.dss.diagnostic.DiagnosticDataFacade;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificateRevocation;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.RevocationReason;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.ValidationPolicy;
import eu.europa.esig.dss.policy.jaxb.BasicSignatureConstraints;
import eu.europa.esig.dss.policy.jaxb.CertificateConstraints;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.policy.jaxb.MultiValuesConstraint;
import eu.europa.esig.dss.policy.jaxb.TimeConstraint;
import eu.europa.esig.dss.policy.jaxb.TimeUnit;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.validation.executor.signature.DefaultSignatureProcessExecutor;
import eu.europa.esig.dss.validation.process.qualification.trust.TrustServiceStatus;
import eu.europa.esig.dss.validation.reports.Reports;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DSS2730ExecutorTest extends AbstractProcessExecutorTest {

    @Test
    void dss2730Test() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/DSS-2730/dss-2730.xml"));
        assertNotNull(diagnosticData);

        String sigTstId = diagnosticData.getUsedTimestamps().get(0).getId();
        String arcTstId = diagnosticData.getUsedTimestamps().get(1).getId();

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        CertificateConstraints signingCertificateConstraints = validationPolicy
                .getSignatureConstraints().getBasicSignatureConstraints().getSigningCertificate();

        TimeConstraint timeConstraint = new TimeConstraint();
        timeConstraint.setLevel(Level.FAIL);
        timeConstraint.setUnit(TimeUnit.DAYS);
        timeConstraint.setValue(0);
        signingCertificateConstraints.setRevocationFreshness(timeConstraint);

        BasicSignatureConstraints timestampConstrains = validationPolicy.getTimestampConstraints().getBasicSignatureConstraints();
        MultiValuesConstraint multiValuesConstraint = new MultiValuesConstraint();
        multiValuesConstraint.getId().add(TrustServiceStatus.GRANTED.getUri());
        timestampConstrains.setTrustServiceStatus(multiValuesConstraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(diagnosticData.getUsedTimestamps().get(1).getProductionTime(),
                simpleReport.getBestSignatureTime(simpleReport.getFirstSignatureId()));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.TOTAL_PASSED, detailedReport.getFinalIndication(detailedReport.getFirstSignatureId()));

        assertEquals(Indication.INDETERMINATE, detailedReport.getBasicValidationIndication(detailedReport.getFirstSignatureId()));
        assertEquals(SubIndication.TRY_LATER, detailedReport.getBasicValidationSubIndication(detailedReport.getFirstSignatureId()));

        eu.europa.esig.dss.detailedreport.jaxb.XmlSignature xmlSignature = detailedReport.getXmlSignatureById(detailedReport.getFirstSignatureId());
        assertNotNull(xmlSignature);

        XmlValidationProcessBasicSignature validationProcessBasicSignature = xmlSignature.getValidationProcessBasicSignature();
        assertEquals(Indication.INDETERMINATE, validationProcessBasicSignature.getConclusion().getIndication());
        assertEquals(SubIndication.TRY_LATER, validationProcessBasicSignature.getConclusion().getSubIndication());
        assertTrue(checkMessageValuePresence(convert(validationProcessBasicSignature.getConclusion().getErrors()),
                i18nProvider.getMessage(MessageTag.BBB_RFC_IRIF_ANS)));

        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertNotNull(signatureBBB);

        XmlXCV xcv = signatureBBB.getXCV();
        assertNotNull(xcv);
        assertEquals(Indication.INDETERMINATE, xcv.getConclusion().getIndication());
        assertEquals(SubIndication.TRY_LATER, xcv.getConclusion().getSubIndication());
        assertTrue(checkMessageValuePresence(convert(xcv.getConclusion().getErrors()),
                i18nProvider.getMessage(MessageTag.BBB_RFC_IRIF_ANS)));

        List<XmlSubXCV> subXCVs = xcv.getSubXCV();
        assertEquals(2, subXCVs.size());

        XmlSubXCV xmlSubXCV = subXCVs.get(0);
        assertEquals(Indication.INDETERMINATE, xmlSubXCV.getConclusion().getIndication());
        assertEquals(SubIndication.TRY_LATER, xmlSubXCV.getConclusion().getSubIndication());

        boolean revocationFreshnessCheckFound = false;
        for (XmlConstraint constraint : xmlSubXCV.getConstraint()) {
            if (MessageTag.BBB_XCV_RFC.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
                assertEquals(MessageTag.BBB_XCV_RFC_ANS.getId(), constraint.getError().getKey());
                revocationFreshnessCheckFound = true;
            } else {
                assertEquals(XmlStatus.OK, constraint.getStatus());
            }
        }
        assertTrue(revocationFreshnessCheckFound);

        XmlValidationProcessLongTermData validationProcessLongTermData = xmlSignature.getValidationProcessLongTermData();
        assertEquals(Indication.INDETERMINATE, validationProcessLongTermData.getConclusion().getIndication());
        assertEquals(SubIndication.TRY_LATER, validationProcessLongTermData.getConclusion().getSubIndication());
        assertTrue(checkMessageValuePresence(convert(validationProcessLongTermData.getConclusion().getErrors()),
                i18nProvider.getMessage(MessageTag.BBB_RFC_IRIF_ANS)));

        boolean basicValidationCheckFound = false;
        revocationFreshnessCheckFound = false;
        for (XmlConstraint constraint : validationProcessLongTermData.getConstraint()) {
            if (MessageTag.ADEST_IBSVPTC.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.WARNING, constraint.getStatus());
                assertEquals(MessageTag.ADEST_IBSVPTC_ANS.getId(), constraint.getWarning().getKey());
                basicValidationCheckFound = true;
            } else if (MessageTag.BBB_XCV_RFC.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
                assertEquals(MessageTag.BBB_XCV_RFC_ANS.getId(), constraint.getError().getKey());
                revocationFreshnessCheckFound = true;
            } else {
                assertEquals(XmlStatus.OK, constraint.getStatus());
            }
        }
        assertTrue(basicValidationCheckFound);
        assertTrue(revocationFreshnessCheckFound);

        XmlValidationProcessArchivalData validationProcessArchivalData = xmlSignature.getValidationProcessArchivalData();
        assertEquals(Indication.PASSED, validationProcessArchivalData.getConclusion().getIndication());

        boolean validTstFound = false;
        boolean invalidTstFound = false;
        for (XmlConstraint constraint : validationProcessArchivalData.getConstraint()) {
            if (MessageTag.ADEST_IBSVPTADC.getId().equals(constraint.getName().getKey())) {
                if (XmlStatus.OK == constraint.getStatus()) {
                    assertEquals(arcTstId, constraint.getId());
                    validTstFound = true;
                } else if (XmlStatus.WARNING == constraint.getStatus()) {
                    assertEquals(sigTstId, constraint.getId());
                    assertEquals(MessageTag.ADEST_IBSVPTADC_ANS.getId(), constraint.getWarning().getKey());
                    invalidTstFound = true;
                }
            } else if (MessageTag.BBB_XCV_RFC.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
                assertEquals(MessageTag.BBB_XCV_RFC_ANS.getId(), constraint.getError().getKey());
            } else if (XmlStatus.IGNORED == constraint.getStatus()) {
                // ignore
            } else {
                assertEquals(XmlStatus.OK, constraint.getStatus());
            }
        }
        assertTrue(validTstFound);
        assertTrue(invalidTstFound);

        XmlPSV psv = signatureBBB.getPSV();
        assertEquals(Indication.PASSED, psv.getConclusion().getIndication());

        revocationFreshnessCheckFound = false;
        for (XmlConstraint constraint : psv.getConstraint()) {
            assertEquals(XmlStatus.OK, constraint.getStatus());
            if (MessageTag.BBB_XCV_RFC.getId().equals(constraint.getName().getKey())) {
                revocationFreshnessCheckFound = true;
            }
        }
        assertTrue(revocationFreshnessCheckFound);

        List<eu.europa.esig.dss.detailedreport.jaxb.XmlTimestamp> timestamps = xmlSignature.getTimestamps();
        assertEquals(2, timestamps.size());

        eu.europa.esig.dss.detailedreport.jaxb.XmlTimestamp xmlTimestamp = timestamps.get(0);
        assertEquals(Indication.INDETERMINATE, xmlTimestamp.getConclusion().getIndication());
        assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, xmlTimestamp.getConclusion().getSubIndication());
        assertTrue(checkMessageValuePresence(convert(xmlTimestamp.getConclusion().getErrors()),
                i18nProvider.getMessage(MessageTag.ASCCM_AR_ANS_ANR, DigestAlgorithm.SHA1, MessageTag.ACCM_POS_TST_SIG)));

        XmlValidationProcessBasicTimestamp validationProcessBasicTimestamp = xmlTimestamp.getValidationProcessBasicTimestamp();
        assertEquals(Indication.INDETERMINATE, validationProcessBasicTimestamp.getConclusion().getIndication());
        assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, validationProcessBasicTimestamp.getConclusion().getSubIndication());
        assertTrue(checkMessageValuePresence(convert(validationProcessBasicTimestamp.getConclusion().getErrors()),
                i18nProvider.getMessage(MessageTag.BBB_XCV_ICTIVRSC_ANS)));
        assertTrue(checkMessageValuePresence(convert(validationProcessBasicTimestamp.getConclusion().getErrors()),
                i18nProvider.getMessage(MessageTag.ASCCM_AR_ANS_ANR, DigestAlgorithm.SHA1, MessageTag.ACCM_POS_TST_SIG)));

        XmlValidationProcessArchivalDataTimestamp validationProcessArchivalDataTimestamp = xmlTimestamp.getValidationProcessArchivalDataTimestamp();
        assertEquals(Indication.INDETERMINATE, validationProcessArchivalDataTimestamp.getConclusion().getIndication());
        assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, validationProcessArchivalDataTimestamp.getConclusion().getSubIndication());
        assertTrue(checkMessageValuePresence(convert(validationProcessArchivalDataTimestamp.getConclusion().getErrors()),
                i18nProvider.getMessage(MessageTag.ASCCM_AR_ANS_ANR, DigestAlgorithm.SHA1, MessageTag.ACCM_POS_TST_SIG)));

        boolean basicTstValidationCheckFound = false;
        boolean pastTstValidationCheckFound = false;
        boolean tavCheckFound = false;
        for (XmlConstraint constraint : validationProcessArchivalDataTimestamp.getConstraint()) {
            if (MessageTag.ADEST_IBSVPTC.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.WARNING, constraint.getStatus());
                assertEquals(MessageTag.ADEST_IBSVPTC_ANS.getId(), constraint.getWarning().getKey());
                basicTstValidationCheckFound = true;
            } else if (MessageTag.PSV_IPTVC.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                pastTstValidationCheckFound = true;
            } else if (MessageTag.BBB_TAV_ISVA.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
                assertEquals(MessageTag.BBB_TAV_ISVA_ANS.getId(), constraint.getError().getKey());
                tavCheckFound = true;
            } else {
                assertEquals(XmlStatus.OK, constraint.getStatus());
            }
        }
        assertTrue(basicTstValidationCheckFound);
        assertTrue(pastTstValidationCheckFound);
        assertTrue(tavCheckFound);

        xmlTimestamp = timestamps.get(1);
        assertEquals(Indication.PASSED, xmlTimestamp.getConclusion().getIndication());

        validationProcessBasicTimestamp = xmlTimestamp.getValidationProcessBasicTimestamp();
        assertEquals(Indication.PASSED, validationProcessBasicTimestamp.getConclusion().getIndication());

        validationProcessArchivalDataTimestamp = xmlTimestamp.getValidationProcessArchivalDataTimestamp();
        assertEquals(Indication.PASSED, validationProcessArchivalDataTimestamp.getConclusion().getIndication());

        checkReports(reports);
    }

    @Test
    void dss2730RevokedTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/DSS-2730/dss-2730-revoked.xml"));
        assertNotNull(diagnosticData);

        String sigTstId = diagnosticData.getUsedTimestamps().get(0).getId();
        String arcTstId = diagnosticData.getUsedTimestamps().get(1).getId();

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        CertificateConstraints signingCertificateConstraints = validationPolicy
                .getSignatureConstraints().getBasicSignatureConstraints().getSigningCertificate();

        TimeConstraint timeConstraint = new TimeConstraint();
        timeConstraint.setLevel(Level.FAIL);
        timeConstraint.setUnit(TimeUnit.DAYS);
        timeConstraint.setValue(0);
        signingCertificateConstraints.setRevocationFreshness(timeConstraint);

        BasicSignatureConstraints timestampConstrains = validationPolicy.getTimestampConstraints().getBasicSignatureConstraints();
        MultiValuesConstraint multiValuesConstraint = new MultiValuesConstraint();
        multiValuesConstraint.getId().add(TrustServiceStatus.GRANTED.getUri());
        timestampConstrains.setTrustServiceStatus(multiValuesConstraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(diagnosticData.getUsedTimestamps().get(1).getProductionTime(),
                simpleReport.getBestSignatureTime(simpleReport.getFirstSignatureId()));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.TOTAL_PASSED, detailedReport.getFinalIndication(detailedReport.getFirstSignatureId()));

        assertEquals(Indication.INDETERMINATE, detailedReport.getBasicValidationIndication(detailedReport.getFirstSignatureId()));
        assertEquals(SubIndication.REVOKED_NO_POE, detailedReport.getBasicValidationSubIndication(detailedReport.getFirstSignatureId()));

        eu.europa.esig.dss.detailedreport.jaxb.XmlSignature xmlSignature = detailedReport.getXmlSignatureById(detailedReport.getFirstSignatureId());
        assertNotNull(xmlSignature);

        XmlValidationProcessBasicSignature validationProcessBasicSignature = xmlSignature.getValidationProcessBasicSignature();
        assertEquals(Indication.INDETERMINATE, validationProcessBasicSignature.getConclusion().getIndication());
        assertEquals(SubIndication.REVOKED_NO_POE, validationProcessBasicSignature.getConclusion().getSubIndication());
        assertTrue(checkMessageValuePresence(convert(validationProcessBasicSignature.getConclusion().getErrors()),
                i18nProvider.getMessage(MessageTag.BBB_XCV_ISCR_ANS)));

        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertNotNull(signatureBBB);

        XmlXCV xcv = signatureBBB.getXCV();
        assertNotNull(xcv);
        assertEquals(Indication.INDETERMINATE, xcv.getConclusion().getIndication());
        assertEquals(SubIndication.REVOKED_NO_POE, xcv.getConclusion().getSubIndication());
        assertTrue(checkMessageValuePresence(convert(xcv.getConclusion().getErrors()),
                i18nProvider.getMessage(MessageTag.BBB_XCV_ISCR_ANS)));

        List<XmlSubXCV> subXCVs = xcv.getSubXCV();
        assertEquals(2, subXCVs.size());

        XmlSubXCV xmlSubXCV = subXCVs.get(0);
        assertEquals(Indication.INDETERMINATE, xmlSubXCV.getConclusion().getIndication());
        assertEquals(SubIndication.REVOKED_NO_POE, xmlSubXCV.getConclusion().getSubIndication());

        boolean certRevokedCheckFound = false;
        boolean revocationFreshnessCheckFound = false;
        for (XmlConstraint constraint : xmlSubXCV.getConstraint()) {
            if (MessageTag.BBB_XCV_ISCR.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
                assertEquals(MessageTag.BBB_XCV_ISCR_ANS.getId(), constraint.getError().getKey());
                certRevokedCheckFound = true;
            } else if (MessageTag.BBB_XCV_RFC.getId().equals(constraint.getName().getKey())) {
                revocationFreshnessCheckFound = true;
            } else {
                assertEquals(XmlStatus.OK, constraint.getStatus());
            }
        }
        assertTrue(certRevokedCheckFound);
        assertFalse(revocationFreshnessCheckFound);

        XmlValidationProcessLongTermData validationProcessLongTermData = xmlSignature.getValidationProcessLongTermData();
        assertEquals(Indication.INDETERMINATE, validationProcessLongTermData.getConclusion().getIndication());
        assertEquals(SubIndication.REVOKED_NO_POE, validationProcessLongTermData.getConclusion().getSubIndication());
        assertTrue(checkMessageValuePresence(convert(validationProcessLongTermData.getConclusion().getErrors()),
                i18nProvider.getMessage(MessageTag.ADEST_IRTPTBST_ANS)));

        boolean basicValidationCheckFound = false;
        certRevokedCheckFound = false;
        for (XmlConstraint constraint : validationProcessLongTermData.getConstraint()) {
            if (MessageTag.ADEST_IBSVPTC.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.WARNING, constraint.getStatus());
                assertEquals(MessageTag.ADEST_IBSVPTC_ANS.getId(), constraint.getWarning().getKey());
                basicValidationCheckFound = true;
            } else if (MessageTag.ADEST_IRTPTBST.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
                assertEquals(MessageTag.ADEST_IRTPTBST_ANS.getId(), constraint.getError().getKey());
                certRevokedCheckFound = true;
            } else if (MessageTag.BBB_XCV_RFC.getId().equals(constraint.getName().getKey())) {
                revocationFreshnessCheckFound = true;
            } else {
                assertEquals(XmlStatus.OK, constraint.getStatus());
            }
        }
        assertTrue(basicValidationCheckFound);
        assertTrue(certRevokedCheckFound);
        assertFalse(revocationFreshnessCheckFound);

        XmlValidationProcessArchivalData validationProcessArchivalData = xmlSignature.getValidationProcessArchivalData();
        assertEquals(Indication.PASSED, validationProcessArchivalData.getConclusion().getIndication());

        boolean validTstFound = false;
        boolean invalidTstFound = false;
        boolean psvCheckFound = false;
        for (XmlConstraint constraint : validationProcessArchivalData.getConstraint()) {
            if (MessageTag.ADEST_IBSVPTADC.getId().equals(constraint.getName().getKey())) {
                if (XmlStatus.OK == constraint.getStatus()) {
                    assertEquals(arcTstId, constraint.getId());
                    validTstFound = true;
                } else if (XmlStatus.WARNING == constraint.getStatus()) {
                    assertEquals(sigTstId, constraint.getId());
                    assertEquals(MessageTag.ADEST_IBSVPTADC_ANS.getId(), constraint.getWarning().getKey());
                    invalidTstFound = true;
                }
            } else if (MessageTag.PSV_IPSVC.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                psvCheckFound = true;
            } else if (XmlStatus.IGNORED == constraint.getStatus()) {
                // ignore
            } else {
                assertEquals(XmlStatus.OK, constraint.getStatus());
            }
        }
        assertTrue(validTstFound);
        assertTrue(invalidTstFound);
        assertTrue(psvCheckFound);

        XmlPSV psv = signatureBBB.getPSV();
        assertEquals(Indication.PASSED, psv.getConclusion().getIndication());

        boolean poeBeforeControlTimeCheckFound = false;
        for (XmlConstraint constraint : psv.getConstraint()) {
            assertEquals(XmlStatus.OK, constraint.getStatus());
            if (MessageTag.PSV_ITPOSVAOBCT.getId().equals(constraint.getName().getKey())) {
                poeBeforeControlTimeCheckFound = true;
            } else if (MessageTag.BBB_XCV_RFC.getId().equals(constraint.getName().getKey())) {
                revocationFreshnessCheckFound = true;
            }
        }
        assertTrue(poeBeforeControlTimeCheckFound);
        assertFalse(revocationFreshnessCheckFound);

        List<eu.europa.esig.dss.detailedreport.jaxb.XmlTimestamp> timestamps = xmlSignature.getTimestamps();
        assertEquals(2, timestamps.size());

        eu.europa.esig.dss.detailedreport.jaxb.XmlTimestamp xmlTimestamp = timestamps.get(0);
        assertEquals(Indication.INDETERMINATE, xmlTimestamp.getConclusion().getIndication());
        assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, xmlTimestamp.getConclusion().getSubIndication());
        assertTrue(checkMessageValuePresence(convert(xmlTimestamp.getConclusion().getErrors()),
                i18nProvider.getMessage(MessageTag.ASCCM_AR_ANS_ANR, DigestAlgorithm.SHA1, MessageTag.ACCM_POS_TST_SIG)));

        XmlValidationProcessBasicTimestamp validationProcessBasicTimestamp = xmlTimestamp.getValidationProcessBasicTimestamp();
        assertEquals(Indication.INDETERMINATE, validationProcessBasicTimestamp.getConclusion().getIndication());
        assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, validationProcessBasicTimestamp.getConclusion().getSubIndication());
        assertTrue(checkMessageValuePresence(convert(validationProcessBasicTimestamp.getConclusion().getErrors()),
                i18nProvider.getMessage(MessageTag.BBB_XCV_ICTIVRSC_ANS)));
        assertTrue(checkMessageValuePresence(convert(validationProcessBasicTimestamp.getConclusion().getErrors()),
                i18nProvider.getMessage(MessageTag.ASCCM_AR_ANS_ANR, DigestAlgorithm.SHA1, MessageTag.ACCM_POS_TST_SIG)));

        XmlValidationProcessArchivalDataTimestamp validationProcessArchivalDataTimestamp = xmlTimestamp.getValidationProcessArchivalDataTimestamp();
        assertEquals(Indication.INDETERMINATE, validationProcessArchivalDataTimestamp.getConclusion().getIndication());
        assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, validationProcessArchivalDataTimestamp.getConclusion().getSubIndication());
        assertTrue(checkMessageValuePresence(convert(validationProcessArchivalDataTimestamp.getConclusion().getErrors()),
                i18nProvider.getMessage(MessageTag.ASCCM_AR_ANS_ANR, DigestAlgorithm.SHA1, MessageTag.ACCM_POS_TST_SIG)));

        boolean basicTstValidationCheckFound = false;
        boolean pastTstValidationCheckFound = false;
        boolean tavCheckFound = false;
        for (XmlConstraint constraint : validationProcessArchivalDataTimestamp.getConstraint()) {
            if (MessageTag.ADEST_IBSVPTC.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.WARNING, constraint.getStatus());
                assertEquals(MessageTag.ADEST_IBSVPTC_ANS.getId(), constraint.getWarning().getKey());
                basicTstValidationCheckFound = true;
            } else if (MessageTag.PSV_IPTVC.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                pastTstValidationCheckFound = true;
            } else if (MessageTag.BBB_TAV_ISVA.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
                assertEquals(MessageTag.BBB_TAV_ISVA_ANS.getId(), constraint.getError().getKey());
                tavCheckFound = true;
            } else {
                assertEquals(XmlStatus.OK, constraint.getStatus());
            }
        }
        assertTrue(basicTstValidationCheckFound);
        assertTrue(pastTstValidationCheckFound);
        assertTrue(tavCheckFound);

        xmlTimestamp = timestamps.get(1);
        assertEquals(Indication.PASSED, xmlTimestamp.getConclusion().getIndication());

        validationProcessBasicTimestamp = xmlTimestamp.getValidationProcessBasicTimestamp();
        assertEquals(Indication.PASSED, validationProcessBasicTimestamp.getConclusion().getIndication());

        validationProcessArchivalDataTimestamp = xmlTimestamp.getValidationProcessArchivalDataTimestamp();
        assertEquals(Indication.PASSED, validationProcessArchivalDataTimestamp.getConclusion().getIndication());

        checkReports(reports);
    }

    @Test
    void dss2730RevokedNotYetValidTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/DSS-2730/dss-2730-revoked-not-yet-valid.xml"));
        assertNotNull(diagnosticData);

        String sigTstId = diagnosticData.getUsedTimestamps().get(0).getId();
        String arcTstId = diagnosticData.getUsedTimestamps().get(1).getId();

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        CertificateConstraints signingCertificateConstraints = validationPolicy
                .getSignatureConstraints().getBasicSignatureConstraints().getSigningCertificate();

        TimeConstraint timeConstraint = new TimeConstraint();
        timeConstraint.setLevel(Level.FAIL);
        timeConstraint.setUnit(TimeUnit.DAYS);
        timeConstraint.setValue(0);
        signingCertificateConstraints.setRevocationFreshness(timeConstraint);

        BasicSignatureConstraints timestampConstrains = validationPolicy.getTimestampConstraints().getBasicSignatureConstraints();
        MultiValuesConstraint multiValuesConstraint = new MultiValuesConstraint();
        multiValuesConstraint.getId().add(TrustServiceStatus.GRANTED.getUri());
        timestampConstrains.setTrustServiceStatus(multiValuesConstraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_FAILED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.NOT_YET_VALID, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.TSV_IBSTAIDOSC_ANS)));
        assertEquals(diagnosticData.getUsedTimestamps().get(1).getProductionTime(),
                simpleReport.getBestSignatureTime(simpleReport.getFirstSignatureId()));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.TOTAL_FAILED, detailedReport.getFinalIndication(detailedReport.getFirstSignatureId()));
        assertEquals(SubIndication.NOT_YET_VALID, detailedReport.getFinalSubIndication(simpleReport.getFirstSignatureId()));

        assertEquals(Indication.INDETERMINATE, detailedReport.getBasicValidationIndication(detailedReport.getFirstSignatureId()));
        assertEquals(SubIndication.REVOKED_NO_POE, detailedReport.getBasicValidationSubIndication(detailedReport.getFirstSignatureId()));

        eu.europa.esig.dss.detailedreport.jaxb.XmlSignature xmlSignature = detailedReport.getXmlSignatureById(detailedReport.getFirstSignatureId());
        assertNotNull(xmlSignature);

        XmlValidationProcessBasicSignature validationProcessBasicSignature = xmlSignature.getValidationProcessBasicSignature();
        assertEquals(Indication.INDETERMINATE, validationProcessBasicSignature.getConclusion().getIndication());
        assertEquals(SubIndication.REVOKED_NO_POE, validationProcessBasicSignature.getConclusion().getSubIndication());
        assertTrue(checkMessageValuePresence(convert(validationProcessBasicSignature.getConclusion().getErrors()),
                i18nProvider.getMessage(MessageTag.BBB_XCV_ISCR_ANS)));

        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertNotNull(signatureBBB);

        XmlXCV xcv = signatureBBB.getXCV();
        assertNotNull(xcv);
        assertEquals(Indication.INDETERMINATE, xcv.getConclusion().getIndication());
        assertEquals(SubIndication.REVOKED_NO_POE, xcv.getConclusion().getSubIndication());
        assertTrue(checkMessageValuePresence(convert(xcv.getConclusion().getErrors()),
                i18nProvider.getMessage(MessageTag.BBB_XCV_ISCR_ANS)));

        List<XmlSubXCV> subXCVs = xcv.getSubXCV();
        assertEquals(2, subXCVs.size());

        XmlSubXCV xmlSubXCV = subXCVs.get(0);
        assertEquals(Indication.INDETERMINATE, xmlSubXCV.getConclusion().getIndication());
        assertEquals(SubIndication.REVOKED_NO_POE, xmlSubXCV.getConclusion().getSubIndication());

        boolean certRevokedCheckFound = false;
        boolean revocationFreshnessCheckFound = false;
        for (XmlConstraint constraint : xmlSubXCV.getConstraint()) {
            if (MessageTag.BBB_XCV_ISCR.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
                assertEquals(MessageTag.BBB_XCV_ISCR_ANS.getId(), constraint.getError().getKey());
                certRevokedCheckFound = true;
            } else if (MessageTag.BBB_XCV_RFC.getId().equals(constraint.getName().getKey())) {
                revocationFreshnessCheckFound = true;
            } else {
                assertEquals(XmlStatus.OK, constraint.getStatus());
            }
        }
        assertTrue(certRevokedCheckFound);
        assertFalse(revocationFreshnessCheckFound);

        XmlValidationProcessLongTermData validationProcessLongTermData = xmlSignature.getValidationProcessLongTermData();
        assertEquals(Indication.INDETERMINATE, validationProcessLongTermData.getConclusion().getIndication());
        assertEquals(SubIndication.REVOKED_NO_POE, validationProcessLongTermData.getConclusion().getSubIndication());
        assertTrue(checkMessageValuePresence(convert(validationProcessLongTermData.getConclusion().getErrors()),
                i18nProvider.getMessage(MessageTag.ADEST_IRTPTBST_ANS)));

        boolean basicValidationCheckFound = false;
        certRevokedCheckFound = false;
        for (XmlConstraint constraint : validationProcessLongTermData.getConstraint()) {
            if (MessageTag.ADEST_IBSVPTC.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.WARNING, constraint.getStatus());
                assertEquals(MessageTag.ADEST_IBSVPTC_ANS.getId(), constraint.getWarning().getKey());
                basicValidationCheckFound = true;
            } else if (MessageTag.ADEST_IRTPTBST.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
                assertEquals(MessageTag.ADEST_IRTPTBST_ANS.getId(), constraint.getError().getKey());
                certRevokedCheckFound = true;
            } else if (MessageTag.BBB_XCV_RFC.getId().equals(constraint.getName().getKey())) {
                revocationFreshnessCheckFound = true;
            } else {
                assertEquals(XmlStatus.OK, constraint.getStatus());
            }
        }
        assertTrue(basicValidationCheckFound);
        assertTrue(certRevokedCheckFound);
        assertFalse(revocationFreshnessCheckFound);

        XmlValidationProcessArchivalData validationProcessArchivalData = xmlSignature.getValidationProcessArchivalData();
        assertEquals(Indication.FAILED, validationProcessArchivalData.getConclusion().getIndication());
        assertEquals(SubIndication.NOT_YET_VALID, validationProcessArchivalData.getConclusion().getSubIndication());
        assertTrue(checkMessageValuePresence(convert(validationProcessArchivalData.getConclusion().getErrors()),
                i18nProvider.getMessage(MessageTag.TSV_IBSTAIDOSC_ANS)));
        assertTrue(checkMessageValuePresence(convert(validationProcessArchivalData.getConclusion().getErrors()),
                i18nProvider.getMessage(MessageTag.PSV_IPSVC_ANS)));

        boolean validTstFound = false;
        boolean invalidTstFound = false;
        boolean psvCheckFound = false;
        for (XmlConstraint constraint : validationProcessArchivalData.getConstraint()) {
            if (MessageTag.ADEST_IBSVPTADC.getId().equals(constraint.getName().getKey())) {
                if (XmlStatus.OK == constraint.getStatus()) {
                    assertEquals(arcTstId, constraint.getId());
                    validTstFound = true;
                } else if (XmlStatus.WARNING == constraint.getStatus()) {
                    assertEquals(sigTstId, constraint.getId());
                    assertEquals(MessageTag.ADEST_IBSVPTADC_ANS.getId(), constraint.getWarning().getKey());
                    invalidTstFound = true;
                }
            } else if (MessageTag.PSV_IPSVC.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
                assertEquals(MessageTag.PSV_IPSVC_ANS.getId(), constraint.getError().getKey());
                psvCheckFound = true;
            } else if (XmlStatus.IGNORED == constraint.getStatus()) {
                // ignore
            } else {
                assertEquals(XmlStatus.OK, constraint.getStatus());
            }
        }
        assertTrue(validTstFound);
        assertTrue(invalidTstFound);
        assertTrue(psvCheckFound);

        XmlPSV psv = signatureBBB.getPSV();
        assertEquals(Indication.FAILED, psv.getConclusion().getIndication());
        assertEquals(SubIndication.NOT_YET_VALID, psv.getConclusion().getSubIndication());
        assertTrue(checkMessageValuePresence(convert(psv.getConclusion().getErrors()),
                i18nProvider.getMessage(MessageTag.TSV_IBSTAIDOSC_ANS)));

        boolean poeBeforeControlTimeCheckFound = false;
        boolean bstNotBeforeCertIssuanceCheckFound = false;
        for (XmlConstraint constraint : psv.getConstraint()) {
            if (MessageTag.PSV_ITPOSVAOBCT.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                poeBeforeControlTimeCheckFound = true;
            } else if (MessageTag.BBB_XCV_RFC.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                revocationFreshnessCheckFound = true;
            } else if (MessageTag.TSV_IBSTAIDOSC.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
                assertEquals(MessageTag.TSV_IBSTAIDOSC_ANS.getId(), constraint.getError().getKey());
                bstNotBeforeCertIssuanceCheckFound = true;
            } else {
                assertEquals(XmlStatus.OK, constraint.getStatus());
            }
        }
        assertTrue(poeBeforeControlTimeCheckFound);
        assertFalse(revocationFreshnessCheckFound);
        assertTrue(bstNotBeforeCertIssuanceCheckFound);

        List<eu.europa.esig.dss.detailedreport.jaxb.XmlTimestamp> timestamps = xmlSignature.getTimestamps();
        assertEquals(2, timestamps.size());

        eu.europa.esig.dss.detailedreport.jaxb.XmlTimestamp xmlTimestamp = timestamps.get(0);
        assertEquals(Indication.INDETERMINATE, xmlTimestamp.getConclusion().getIndication());
        assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, xmlTimestamp.getConclusion().getSubIndication());
        assertTrue(checkMessageValuePresence(convert(xmlTimestamp.getConclusion().getErrors()),
                i18nProvider.getMessage(MessageTag.ASCCM_AR_ANS_ANR, DigestAlgorithm.SHA1, MessageTag.ACCM_POS_TST_SIG)));

        XmlValidationProcessBasicTimestamp validationProcessBasicTimestamp = xmlTimestamp.getValidationProcessBasicTimestamp();
        assertEquals(Indication.INDETERMINATE, validationProcessBasicTimestamp.getConclusion().getIndication());
        assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, validationProcessBasicTimestamp.getConclusion().getSubIndication());
        assertTrue(checkMessageValuePresence(convert(validationProcessBasicTimestamp.getConclusion().getErrors()),
                i18nProvider.getMessage(MessageTag.BBB_XCV_ICTIVRSC_ANS)));
        assertTrue(checkMessageValuePresence(convert(validationProcessBasicTimestamp.getConclusion().getErrors()),
                i18nProvider.getMessage(MessageTag.ASCCM_AR_ANS_ANR, DigestAlgorithm.SHA1, MessageTag.ACCM_POS_TST_SIG)));

        XmlValidationProcessArchivalDataTimestamp validationProcessArchivalDataTimestamp = xmlTimestamp.getValidationProcessArchivalDataTimestamp();
        assertEquals(Indication.INDETERMINATE, validationProcessArchivalDataTimestamp.getConclusion().getIndication());
        assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, validationProcessArchivalDataTimestamp.getConclusion().getSubIndication());
        assertTrue(checkMessageValuePresence(convert(validationProcessArchivalDataTimestamp.getConclusion().getErrors()),
                i18nProvider.getMessage(MessageTag.ASCCM_AR_ANS_ANR, DigestAlgorithm.SHA1, MessageTag.ACCM_POS_TST_SIG)));

        boolean basicTstValidationCheckFound = false;
        boolean pastTstValidationCheckFound = false;
        boolean tavCheckFound = false;
        for (XmlConstraint constraint : validationProcessArchivalDataTimestamp.getConstraint()) {
            if (MessageTag.ADEST_IBSVPTC.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.WARNING, constraint.getStatus());
                assertEquals(MessageTag.ADEST_IBSVPTC_ANS.getId(), constraint.getWarning().getKey());
                basicTstValidationCheckFound = true;
            } else if (MessageTag.PSV_IPTVC.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                pastTstValidationCheckFound = true;
            } else if (MessageTag.BBB_TAV_ISVA.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
                assertEquals(MessageTag.BBB_TAV_ISVA_ANS.getId(), constraint.getError().getKey());
                tavCheckFound = true;
            } else {
                assertEquals(XmlStatus.OK, constraint.getStatus());
            }
        }
        assertTrue(basicTstValidationCheckFound);
        assertTrue(pastTstValidationCheckFound);
        assertTrue(tavCheckFound);

        xmlTimestamp = timestamps.get(1);
        assertEquals(Indication.PASSED, xmlTimestamp.getConclusion().getIndication());

        validationProcessBasicTimestamp = xmlTimestamp.getValidationProcessBasicTimestamp();
        assertEquals(Indication.PASSED, validationProcessBasicTimestamp.getConclusion().getIndication());

        validationProcessArchivalDataTimestamp = xmlTimestamp.getValidationProcessArchivalDataTimestamp();
        assertEquals(Indication.PASSED, validationProcessArchivalDataTimestamp.getConclusion().getIndication());

        checkReports(reports);
    }

    @Test
    void dss2730RevokedExpiredTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/DSS-2730/dss-2730-revoked-expired.xml"));
        assertNotNull(diagnosticData);

        String sigTstId = diagnosticData.getUsedTimestamps().get(0).getId();
        String arcTstId = diagnosticData.getUsedTimestamps().get(1).getId();

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        CertificateConstraints signingCertificateConstraints = validationPolicy
                .getSignatureConstraints().getBasicSignatureConstraints().getSigningCertificate();

        TimeConstraint timeConstraint = new TimeConstraint();
        timeConstraint.setLevel(Level.FAIL);
        timeConstraint.setUnit(TimeUnit.DAYS);
        timeConstraint.setValue(0);
        signingCertificateConstraints.setRevocationFreshness(timeConstraint);

        BasicSignatureConstraints timestampConstrains = validationPolicy.getTimestampConstraints().getBasicSignatureConstraints();
        MultiValuesConstraint multiValuesConstraint = new MultiValuesConstraint();
        multiValuesConstraint.getId().add(TrustServiceStatus.GRANTED.getUri());
        timestampConstrains.setTrustServiceStatus(multiValuesConstraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.TSV_ISCNVABST_ANS)));
        assertEquals(diagnosticData.getUsedTimestamps().get(1).getProductionTime(),
                simpleReport.getBestSignatureTime(simpleReport.getFirstSignatureId()));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.INDETERMINATE, detailedReport.getFinalIndication(detailedReport.getFirstSignatureId()));
        assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, detailedReport.getFinalSubIndication(simpleReport.getFirstSignatureId()));

        assertEquals(Indication.INDETERMINATE, detailedReport.getBasicValidationIndication(detailedReport.getFirstSignatureId()));
        assertEquals(SubIndication.REVOKED_NO_POE, detailedReport.getBasicValidationSubIndication(detailedReport.getFirstSignatureId()));

        eu.europa.esig.dss.detailedreport.jaxb.XmlSignature xmlSignature = detailedReport.getXmlSignatureById(detailedReport.getFirstSignatureId());
        assertNotNull(xmlSignature);

        XmlValidationProcessBasicSignature validationProcessBasicSignature = xmlSignature.getValidationProcessBasicSignature();
        assertEquals(Indication.INDETERMINATE, validationProcessBasicSignature.getConclusion().getIndication());
        assertEquals(SubIndication.REVOKED_NO_POE, validationProcessBasicSignature.getConclusion().getSubIndication());
        assertTrue(checkMessageValuePresence(convert(validationProcessBasicSignature.getConclusion().getErrors()),
                i18nProvider.getMessage(MessageTag.BBB_XCV_ISCR_ANS)));

        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertNotNull(signatureBBB);

        XmlXCV xcv = signatureBBB.getXCV();
        assertNotNull(xcv);
        assertEquals(Indication.INDETERMINATE, xcv.getConclusion().getIndication());
        assertEquals(SubIndication.REVOKED_NO_POE, xcv.getConclusion().getSubIndication());
        assertTrue(checkMessageValuePresence(convert(xcv.getConclusion().getErrors()),
                i18nProvider.getMessage(MessageTag.BBB_XCV_ISCR_ANS)));

        List<XmlSubXCV> subXCVs = xcv.getSubXCV();
        assertEquals(2, subXCVs.size());

        XmlSubXCV xmlSubXCV = subXCVs.get(0);
        assertEquals(Indication.INDETERMINATE, xmlSubXCV.getConclusion().getIndication());
        assertEquals(SubIndication.REVOKED_NO_POE, xmlSubXCV.getConclusion().getSubIndication());

        boolean certRevokedCheckFound = false;
        boolean revocationFreshnessCheckFound = false;
        for (XmlConstraint constraint : xmlSubXCV.getConstraint()) {
            if (MessageTag.BBB_XCV_ISCR.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
                assertEquals(MessageTag.BBB_XCV_ISCR_ANS.getId(), constraint.getError().getKey());
                certRevokedCheckFound = true;
            } else if (MessageTag.BBB_XCV_RFC.getId().equals(constraint.getName().getKey())) {
                revocationFreshnessCheckFound = true;
            } else {
                assertEquals(XmlStatus.OK, constraint.getStatus());
            }
        }
        assertTrue(certRevokedCheckFound);
        assertFalse(revocationFreshnessCheckFound);

        XmlValidationProcessLongTermData validationProcessLongTermData = xmlSignature.getValidationProcessLongTermData();
        assertEquals(Indication.INDETERMINATE, validationProcessLongTermData.getConclusion().getIndication());
        assertEquals(SubIndication.REVOKED_NO_POE, validationProcessLongTermData.getConclusion().getSubIndication());
        assertTrue(checkMessageValuePresence(convert(validationProcessLongTermData.getConclusion().getErrors()),
                i18nProvider.getMessage(MessageTag.ADEST_IRTPTBST_ANS)));

        boolean basicValidationCheckFound = false;
        certRevokedCheckFound = false;
        for (XmlConstraint constraint : validationProcessLongTermData.getConstraint()) {
            if (MessageTag.ADEST_IBSVPTC.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.WARNING, constraint.getStatus());
                assertEquals(MessageTag.ADEST_IBSVPTC_ANS.getId(), constraint.getWarning().getKey());
                basicValidationCheckFound = true;
            } else if (MessageTag.ADEST_IRTPTBST.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
                assertEquals(MessageTag.ADEST_IRTPTBST_ANS.getId(), constraint.getError().getKey());
                certRevokedCheckFound = true;
            } else if (MessageTag.BBB_XCV_RFC.getId().equals(constraint.getName().getKey())) {
                revocationFreshnessCheckFound = true;
            } else {
                assertEquals(XmlStatus.OK, constraint.getStatus());
            }
        }
        assertTrue(basicValidationCheckFound);
        assertTrue(certRevokedCheckFound);
        assertFalse(revocationFreshnessCheckFound);

        XmlValidationProcessArchivalData validationProcessArchivalData = xmlSignature.getValidationProcessArchivalData();
        assertEquals(Indication.INDETERMINATE, validationProcessArchivalData.getConclusion().getIndication());
        assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, validationProcessArchivalData.getConclusion().getSubIndication());
        assertTrue(checkMessageValuePresence(convert(validationProcessArchivalData.getConclusion().getErrors()),
                i18nProvider.getMessage(MessageTag.TSV_ISCNVABST_ANS)));
        assertTrue(checkMessageValuePresence(convert(validationProcessArchivalData.getConclusion().getErrors()),
                i18nProvider.getMessage(MessageTag.PSV_IPSVC_ANS)));

        boolean validTstFound = false;
        boolean invalidTstFound = false;
        boolean psvCheckFound = false;
        for (XmlConstraint constraint : validationProcessArchivalData.getConstraint()) {
            if (MessageTag.ADEST_IBSVPTADC.getId().equals(constraint.getName().getKey())) {
                if (XmlStatus.OK == constraint.getStatus()) {
                    assertEquals(arcTstId, constraint.getId());
                    validTstFound = true;
                } else if (XmlStatus.WARNING == constraint.getStatus()) {
                    assertEquals(sigTstId, constraint.getId());
                    assertEquals(MessageTag.ADEST_IBSVPTADC_ANS.getId(), constraint.getWarning().getKey());
                    invalidTstFound = true;
                }
            } else if (MessageTag.PSV_IPSVC.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
                assertEquals(MessageTag.PSV_IPSVC_ANS.getId(), constraint.getError().getKey());
                psvCheckFound = true;
            } else if (XmlStatus.IGNORED == constraint.getStatus()) {
                // ignore
            } else {
                assertEquals(XmlStatus.OK, constraint.getStatus());
            }
        }
        assertTrue(validTstFound);
        assertTrue(invalidTstFound);
        assertTrue(psvCheckFound);

        XmlPSV psv = signatureBBB.getPSV();
        assertEquals(Indication.INDETERMINATE, psv.getConclusion().getIndication());
        assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, psv.getConclusion().getSubIndication());
        assertTrue(checkMessageValuePresence(convert(psv.getConclusion().getErrors()),
                i18nProvider.getMessage(MessageTag.TSV_ISCNVABST_ANS)));

        boolean poeBeforeControlTimeCheckFound = false;
        boolean bstNotAfterCertNotAfterCheckFound = false;
        for (XmlConstraint constraint : psv.getConstraint()) {
            if (MessageTag.PSV_ITPOSVAOBCT.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                poeBeforeControlTimeCheckFound = true;
            } else if (MessageTag.BBB_XCV_RFC.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                revocationFreshnessCheckFound = true;
            } else if (MessageTag.TSV_ISCNVABST.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
                assertEquals(MessageTag.TSV_ISCNVABST_ANS.getId(), constraint.getError().getKey());
                bstNotAfterCertNotAfterCheckFound = true;
            } else {
                assertEquals(XmlStatus.OK, constraint.getStatus());
            }
        }
        assertTrue(poeBeforeControlTimeCheckFound);
        assertFalse(revocationFreshnessCheckFound);
        assertTrue(bstNotAfterCertNotAfterCheckFound);

        List<eu.europa.esig.dss.detailedreport.jaxb.XmlTimestamp> timestamps = xmlSignature.getTimestamps();
        assertEquals(2, timestamps.size());

        eu.europa.esig.dss.detailedreport.jaxb.XmlTimestamp xmlTimestamp = timestamps.get(0);
        assertEquals(Indication.INDETERMINATE, xmlTimestamp.getConclusion().getIndication());
        assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, xmlTimestamp.getConclusion().getSubIndication());
        assertTrue(checkMessageValuePresence(convert(xmlTimestamp.getConclusion().getErrors()),
                i18nProvider.getMessage(MessageTag.ASCCM_AR_ANS_ANR, DigestAlgorithm.SHA1, MessageTag.ACCM_POS_TST_SIG)));

        XmlValidationProcessBasicTimestamp validationProcessBasicTimestamp = xmlTimestamp.getValidationProcessBasicTimestamp();
        assertEquals(Indication.INDETERMINATE, validationProcessBasicTimestamp.getConclusion().getIndication());
        assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, validationProcessBasicTimestamp.getConclusion().getSubIndication());
        assertTrue(checkMessageValuePresence(convert(validationProcessBasicTimestamp.getConclusion().getErrors()),
                i18nProvider.getMessage(MessageTag.BBB_XCV_ICTIVRSC_ANS)));
        assertTrue(checkMessageValuePresence(convert(validationProcessBasicTimestamp.getConclusion().getErrors()),
                i18nProvider.getMessage(MessageTag.ASCCM_AR_ANS_ANR, DigestAlgorithm.SHA1, MessageTag.ACCM_POS_TST_SIG)));

        XmlValidationProcessArchivalDataTimestamp validationProcessArchivalDataTimestamp = xmlTimestamp.getValidationProcessArchivalDataTimestamp();
        assertEquals(Indication.INDETERMINATE, validationProcessArchivalDataTimestamp.getConclusion().getIndication());
        assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, validationProcessArchivalDataTimestamp.getConclusion().getSubIndication());
        assertTrue(checkMessageValuePresence(convert(validationProcessArchivalDataTimestamp.getConclusion().getErrors()),
                i18nProvider.getMessage(MessageTag.ASCCM_AR_ANS_ANR, DigestAlgorithm.SHA1, MessageTag.ACCM_POS_TST_SIG)));

        boolean basicTstValidationCheckFound = false;
        boolean pastTstValidationCheckFound = false;
        boolean tavCheckFound = false;
        for (XmlConstraint constraint : validationProcessArchivalDataTimestamp.getConstraint()) {
            if (MessageTag.ADEST_IBSVPTC.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.WARNING, constraint.getStatus());
                assertEquals(MessageTag.ADEST_IBSVPTC_ANS.getId(), constraint.getWarning().getKey());
                basicTstValidationCheckFound = true;
            } else if (MessageTag.PSV_IPTVC.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                pastTstValidationCheckFound = true;
            } else if (MessageTag.BBB_TAV_ISVA.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
                assertEquals(MessageTag.BBB_TAV_ISVA_ANS.getId(), constraint.getError().getKey());
                tavCheckFound = true;
            } else {
                assertEquals(XmlStatus.OK, constraint.getStatus());
            }
        }
        assertTrue(basicTstValidationCheckFound);
        assertTrue(pastTstValidationCheckFound);
        assertTrue(tavCheckFound);

        xmlTimestamp = timestamps.get(1);
        assertEquals(Indication.PASSED, xmlTimestamp.getConclusion().getIndication());

        validationProcessBasicTimestamp = xmlTimestamp.getValidationProcessBasicTimestamp();
        assertEquals(Indication.PASSED, validationProcessBasicTimestamp.getConclusion().getIndication());

        validationProcessArchivalDataTimestamp = xmlTimestamp.getValidationProcessArchivalDataTimestamp();
        assertEquals(Indication.PASSED, validationProcessArchivalDataTimestamp.getConclusion().getIndication());

        checkReports(reports);
    }

    @Test
    void dss2730SuspendedTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/DSS-2730/dss-2730-revoked.xml"));
        assertNotNull(diagnosticData);

        String sigTstId = diagnosticData.getUsedTimestamps().get(0).getId();
        String arcTstId = diagnosticData.getUsedTimestamps().get(1).getId();

        XmlCertificateRevocation xmlCertificateRevocation = diagnosticData.getSignatures().get(0)
                .getSigningCertificate().getCertificate().getRevocations().get(1);
        xmlCertificateRevocation.setReason(RevocationReason.CERTIFICATE_HOLD);

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        CertificateConstraints signingCertificateConstraints = validationPolicy
                .getSignatureConstraints().getBasicSignatureConstraints().getSigningCertificate();

        TimeConstraint timeConstraint = new TimeConstraint();
        timeConstraint.setLevel(Level.FAIL);
        timeConstraint.setUnit(TimeUnit.DAYS);
        timeConstraint.setValue(0);
        signingCertificateConstraints.setRevocationFreshness(timeConstraint);

        BasicSignatureConstraints timestampConstrains = validationPolicy.getTimestampConstraints().getBasicSignatureConstraints();
        MultiValuesConstraint multiValuesConstraint = new MultiValuesConstraint();
        multiValuesConstraint.getId().add(TrustServiceStatus.GRANTED.getUri());
        timestampConstrains.setTrustServiceStatus(multiValuesConstraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(diagnosticData.getUsedTimestamps().get(1).getProductionTime(),
                simpleReport.getBestSignatureTime(simpleReport.getFirstSignatureId()));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.TOTAL_PASSED, detailedReport.getFinalIndication(detailedReport.getFirstSignatureId()));

        assertEquals(Indication.INDETERMINATE, detailedReport.getBasicValidationIndication(detailedReport.getFirstSignatureId()));
        assertEquals(SubIndication.TRY_LATER, detailedReport.getBasicValidationSubIndication(detailedReport.getFirstSignatureId()));

        eu.europa.esig.dss.detailedreport.jaxb.XmlSignature xmlSignature = detailedReport.getXmlSignatureById(detailedReport.getFirstSignatureId());
        assertNotNull(xmlSignature);

        XmlValidationProcessBasicSignature validationProcessBasicSignature = xmlSignature.getValidationProcessBasicSignature();
        assertEquals(Indication.INDETERMINATE, validationProcessBasicSignature.getConclusion().getIndication());
        assertEquals(SubIndication.TRY_LATER, validationProcessBasicSignature.getConclusion().getSubIndication());
        assertTrue(checkMessageValuePresence(convert(validationProcessBasicSignature.getConclusion().getErrors()),
                i18nProvider.getMessage(MessageTag.BBB_XCV_ISCOH_ANS)));

        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertNotNull(signatureBBB);

        XmlXCV xcv = signatureBBB.getXCV();
        assertNotNull(xcv);
        assertEquals(Indication.INDETERMINATE, xcv.getConclusion().getIndication());
        assertEquals(SubIndication.TRY_LATER, xcv.getConclusion().getSubIndication());
        assertTrue(checkMessageValuePresence(convert(xcv.getConclusion().getErrors()),
                i18nProvider.getMessage(MessageTag.BBB_XCV_ISCOH_ANS)));

        List<XmlSubXCV> subXCVs = xcv.getSubXCV();
        assertEquals(2, subXCVs.size());

        XmlSubXCV xmlSubXCV = subXCVs.get(0);
        assertEquals(Indication.INDETERMINATE, xmlSubXCV.getConclusion().getIndication());
        assertEquals(SubIndication.TRY_LATER, xmlSubXCV.getConclusion().getSubIndication());

        boolean certOnHoldCheckFound = false;
        boolean revocationFreshnessCheckFound = false;
        for (XmlConstraint constraint : xmlSubXCV.getConstraint()) {
            if (MessageTag.BBB_XCV_ISCOH.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
                assertEquals(MessageTag.BBB_XCV_ISCOH_ANS.getId(), constraint.getError().getKey());
                certOnHoldCheckFound = true;
            } else if (MessageTag.BBB_XCV_RFC.getId().equals(constraint.getName().getKey())) {
                revocationFreshnessCheckFound = true;
            } else {
                assertEquals(XmlStatus.OK, constraint.getStatus());
            }
        }
        assertTrue(certOnHoldCheckFound);
        assertFalse(revocationFreshnessCheckFound);

        XmlValidationProcessLongTermData validationProcessLongTermData = xmlSignature.getValidationProcessLongTermData();
        assertEquals(Indication.INDETERMINATE, validationProcessLongTermData.getConclusion().getIndication());
        assertEquals(SubIndication.TRY_LATER, validationProcessLongTermData.getConclusion().getSubIndication());
        assertTrue(checkMessageValuePresence(convert(validationProcessLongTermData.getConclusion().getErrors()),
                i18nProvider.getMessage(MessageTag.ADEST_ISTPTBST_ANS)));

        boolean basicValidationCheckFound = false;
        certOnHoldCheckFound = false;
        for (XmlConstraint constraint : validationProcessLongTermData.getConstraint()) {
            if (MessageTag.ADEST_IBSVPTC.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.WARNING, constraint.getStatus());
                assertEquals(MessageTag.ADEST_IBSVPTC_ANS.getId(), constraint.getWarning().getKey());
                basicValidationCheckFound = true;
            } else if (MessageTag.ADEST_ISTPTBST.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
                assertEquals(MessageTag.ADEST_ISTPTBST_ANS.getId(), constraint.getError().getKey());
                certOnHoldCheckFound = true;
            } else if (MessageTag.BBB_XCV_RFC.getId().equals(constraint.getName().getKey())) {
                revocationFreshnessCheckFound = true;
            } else {
                assertEquals(XmlStatus.OK, constraint.getStatus());
            }
        }
        assertTrue(basicValidationCheckFound);
        assertTrue(certOnHoldCheckFound);
        assertFalse(revocationFreshnessCheckFound);

        XmlValidationProcessArchivalData validationProcessArchivalData = xmlSignature.getValidationProcessArchivalData();
        assertEquals(Indication.PASSED, validationProcessArchivalData.getConclusion().getIndication());

        boolean validTstFound = false;
        boolean invalidTstFound = false;
        boolean psvCheckFound = false;
        for (XmlConstraint constraint : validationProcessArchivalData.getConstraint()) {
            if (MessageTag.ADEST_IBSVPTADC.getId().equals(constraint.getName().getKey())) {
                if (XmlStatus.OK == constraint.getStatus()) {
                    assertEquals(arcTstId, constraint.getId());
                    validTstFound = true;
                } else if (XmlStatus.WARNING == constraint.getStatus()) {
                    assertEquals(sigTstId, constraint.getId());
                    assertEquals(MessageTag.ADEST_IBSVPTADC_ANS.getId(), constraint.getWarning().getKey());
                    invalidTstFound = true;
                }
            } else if (MessageTag.PSV_IPSVC.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                psvCheckFound = true;
            } else if (XmlStatus.IGNORED == constraint.getStatus()) {
                // ignore
            } else {
                assertEquals(XmlStatus.OK, constraint.getStatus());
            }
        }
        assertTrue(validTstFound);
        assertTrue(invalidTstFound);
        assertTrue(psvCheckFound);

        XmlPSV psv = signatureBBB.getPSV();
        assertEquals(Indication.PASSED, psv.getConclusion().getIndication());

        boolean poeBeforeControlTimeCheckFound = false;
        for (XmlConstraint constraint : psv.getConstraint()) {
            assertEquals(XmlStatus.OK, constraint.getStatus());
            if (MessageTag.PSV_ITPOSVAOBCT.getId().equals(constraint.getName().getKey())) {
                poeBeforeControlTimeCheckFound = true;
            } else if (MessageTag.BBB_XCV_RFC.getId().equals(constraint.getName().getKey())) {
                revocationFreshnessCheckFound = true;
            }
        }
        assertTrue(poeBeforeControlTimeCheckFound);
        assertFalse(revocationFreshnessCheckFound);

        List<eu.europa.esig.dss.detailedreport.jaxb.XmlTimestamp> timestamps = xmlSignature.getTimestamps();
        assertEquals(2, timestamps.size());

        eu.europa.esig.dss.detailedreport.jaxb.XmlTimestamp xmlTimestamp = timestamps.get(0);
        assertEquals(Indication.INDETERMINATE, xmlTimestamp.getConclusion().getIndication());
        assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, xmlTimestamp.getConclusion().getSubIndication());
        assertTrue(checkMessageValuePresence(convert(xmlTimestamp.getConclusion().getErrors()),
                i18nProvider.getMessage(MessageTag.ASCCM_AR_ANS_ANR, DigestAlgorithm.SHA1, MessageTag.ACCM_POS_TST_SIG)));

        XmlValidationProcessBasicTimestamp validationProcessBasicTimestamp = xmlTimestamp.getValidationProcessBasicTimestamp();
        assertEquals(Indication.INDETERMINATE, validationProcessBasicTimestamp.getConclusion().getIndication());
        assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, validationProcessBasicTimestamp.getConclusion().getSubIndication());
        assertTrue(checkMessageValuePresence(convert(validationProcessBasicTimestamp.getConclusion().getErrors()),
                i18nProvider.getMessage(MessageTag.BBB_XCV_ICTIVRSC_ANS)));
        assertTrue(checkMessageValuePresence(convert(validationProcessBasicTimestamp.getConclusion().getErrors()),
                i18nProvider.getMessage(MessageTag.ASCCM_AR_ANS_ANR, DigestAlgorithm.SHA1, MessageTag.ACCM_POS_TST_SIG)));

        XmlValidationProcessArchivalDataTimestamp validationProcessArchivalDataTimestamp = xmlTimestamp.getValidationProcessArchivalDataTimestamp();
        assertEquals(Indication.INDETERMINATE, validationProcessArchivalDataTimestamp.getConclusion().getIndication());
        assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, validationProcessArchivalDataTimestamp.getConclusion().getSubIndication());
        assertTrue(checkMessageValuePresence(convert(validationProcessArchivalDataTimestamp.getConclusion().getErrors()),
                i18nProvider.getMessage(MessageTag.ASCCM_AR_ANS_ANR, DigestAlgorithm.SHA1, MessageTag.ACCM_POS_TST_SIG)));

        boolean basicTstValidationCheckFound = false;
        boolean pastTstValidationCheckFound = false;
        boolean tavCheckFound = false;
        for (XmlConstraint constraint : validationProcessArchivalDataTimestamp.getConstraint()) {
            if (MessageTag.ADEST_IBSVPTC.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.WARNING, constraint.getStatus());
                assertEquals(MessageTag.ADEST_IBSVPTC_ANS.getId(), constraint.getWarning().getKey());
                basicTstValidationCheckFound = true;
            } else if (MessageTag.PSV_IPTVC.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                pastTstValidationCheckFound = true;
            } else if (MessageTag.BBB_TAV_ISVA.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
                assertEquals(MessageTag.BBB_TAV_ISVA_ANS.getId(), constraint.getError().getKey());
                tavCheckFound = true;
            } else {
                assertEquals(XmlStatus.OK, constraint.getStatus());
            }
        }
        assertTrue(basicTstValidationCheckFound);
        assertTrue(pastTstValidationCheckFound);
        assertTrue(tavCheckFound);

        xmlTimestamp = timestamps.get(1);
        assertEquals(Indication.PASSED, xmlTimestamp.getConclusion().getIndication());

        validationProcessBasicTimestamp = xmlTimestamp.getValidationProcessBasicTimestamp();
        assertEquals(Indication.PASSED, validationProcessBasicTimestamp.getConclusion().getIndication());

        validationProcessArchivalDataTimestamp = xmlTimestamp.getValidationProcessArchivalDataTimestamp();
        assertEquals(Indication.PASSED, validationProcessArchivalDataTimestamp.getConclusion().getIndication());

        checkReports(reports);
    }

    @Test
    void dss2730TimestampDelayTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/DSS-2730/dss-2730.xml"));
        assertNotNull(diagnosticData);

        String sigTstId = diagnosticData.getUsedTimestamps().get(0).getId();
        String arcTstId = diagnosticData.getUsedTimestamps().get(1).getId();

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        CertificateConstraints signingCertificateConstraints = validationPolicy
                .getSignatureConstraints().getBasicSignatureConstraints().getSigningCertificate();

        TimeConstraint timeConstraint = new TimeConstraint();
        timeConstraint.setLevel(Level.FAIL);
        timeConstraint.setUnit(TimeUnit.DAYS);
        timeConstraint.setValue(0);
        signingCertificateConstraints.setRevocationFreshness(timeConstraint);

        BasicSignatureConstraints timestampConstrains = validationPolicy.getTimestampConstraints().getBasicSignatureConstraints();
        MultiValuesConstraint multiValuesConstraint = new MultiValuesConstraint();
        multiValuesConstraint.getId().add(TrustServiceStatus.GRANTED.getUri());
        timestampConstrains.setTrustServiceStatus(multiValuesConstraint);

        timeConstraint = new TimeConstraint();
        timeConstraint.setLevel(Level.FAIL);
        timeConstraint.setUnit(TimeUnit.HOURS);
        timeConstraint.setValue(2);
        validationPolicy.getTimestampConstraints().setTimestampDelay(timeConstraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(diagnosticData.getUsedTimestamps().get(1).getProductionTime(),
                simpleReport.getBestSignatureTime(simpleReport.getFirstSignatureId()));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.TOTAL_PASSED, detailedReport.getFinalIndication(detailedReport.getFirstSignatureId()));

        assertEquals(Indication.INDETERMINATE, detailedReport.getBasicValidationIndication(detailedReport.getFirstSignatureId()));
        assertEquals(SubIndication.TRY_LATER, detailedReport.getBasicValidationSubIndication(detailedReport.getFirstSignatureId()));

        eu.europa.esig.dss.detailedreport.jaxb.XmlSignature xmlSignature = detailedReport.getXmlSignatureById(detailedReport.getFirstSignatureId());
        assertNotNull(xmlSignature);

        XmlValidationProcessBasicSignature validationProcessBasicSignature = xmlSignature.getValidationProcessBasicSignature();
        assertEquals(Indication.INDETERMINATE, validationProcessBasicSignature.getConclusion().getIndication());
        assertEquals(SubIndication.TRY_LATER, validationProcessBasicSignature.getConclusion().getSubIndication());
        assertTrue(checkMessageValuePresence(convert(validationProcessBasicSignature.getConclusion().getErrors()),
                i18nProvider.getMessage(MessageTag.BBB_RFC_IRIF_ANS)));

        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertNotNull(signatureBBB);

        XmlXCV xcv = signatureBBB.getXCV();
        assertNotNull(xcv);
        assertEquals(Indication.INDETERMINATE, xcv.getConclusion().getIndication());
        assertEquals(SubIndication.TRY_LATER, xcv.getConclusion().getSubIndication());
        assertTrue(checkMessageValuePresence(convert(xcv.getConclusion().getErrors()),
                i18nProvider.getMessage(MessageTag.BBB_RFC_IRIF_ANS)));

        List<XmlSubXCV> subXCVs = xcv.getSubXCV();
        assertEquals(2, subXCVs.size());

        XmlSubXCV xmlSubXCV = subXCVs.get(0);
        assertEquals(Indication.INDETERMINATE, xmlSubXCV.getConclusion().getIndication());
        assertEquals(SubIndication.TRY_LATER, xmlSubXCV.getConclusion().getSubIndication());

        boolean revocationFreshnessCheckFound = false;
        for (XmlConstraint constraint : xmlSubXCV.getConstraint()) {
            if (MessageTag.BBB_XCV_RFC.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
                assertEquals(MessageTag.BBB_XCV_RFC_ANS.getId(), constraint.getError().getKey());
                revocationFreshnessCheckFound = true;
            } else {
                assertEquals(XmlStatus.OK, constraint.getStatus());
            }
        }
        assertTrue(revocationFreshnessCheckFound);

        XmlValidationProcessLongTermData validationProcessLongTermData = xmlSignature.getValidationProcessLongTermData();
        assertEquals(Indication.INDETERMINATE, validationProcessLongTermData.getConclusion().getIndication());
        assertEquals(SubIndication.TRY_LATER, validationProcessLongTermData.getConclusion().getSubIndication());
        assertTrue(checkMessageValuePresence(convert(validationProcessLongTermData.getConclusion().getErrors()),
                i18nProvider.getMessage(MessageTag.BBB_RFC_IRIF_ANS)));

        boolean basicValidationCheckFound = false;
        revocationFreshnessCheckFound = false;
        for (XmlConstraint constraint : validationProcessLongTermData.getConstraint()) {
            if (MessageTag.ADEST_IBSVPTC.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.WARNING, constraint.getStatus());
                assertEquals(MessageTag.ADEST_IBSVPTC_ANS.getId(), constraint.getWarning().getKey());
                basicValidationCheckFound = true;
            } else if (MessageTag.BBB_XCV_RFC.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
                assertEquals(MessageTag.BBB_XCV_RFC_ANS.getId(), constraint.getError().getKey());
                revocationFreshnessCheckFound = true;
            } else {
                assertEquals(XmlStatus.OK, constraint.getStatus());
            }
        }
        assertTrue(basicValidationCheckFound);
        assertTrue(revocationFreshnessCheckFound);

        XmlValidationProcessArchivalData validationProcessArchivalData = xmlSignature.getValidationProcessArchivalData();
        assertEquals(Indication.PASSED, validationProcessArchivalData.getConclusion().getIndication());

        boolean validTstFound = false;
        boolean invalidTstFound = false;
        for (XmlConstraint constraint : validationProcessArchivalData.getConstraint()) {
            if (MessageTag.ADEST_IBSVPTADC.getId().equals(constraint.getName().getKey())) {
                if (XmlStatus.OK == constraint.getStatus()) {
                    assertEquals(arcTstId, constraint.getId());
                    validTstFound = true;
                } else if (XmlStatus.WARNING == constraint.getStatus()) {
                    assertEquals(sigTstId, constraint.getId());
                    assertEquals(MessageTag.ADEST_IBSVPTADC_ANS.getId(), constraint.getWarning().getKey());
                    invalidTstFound = true;
                }
            } else if (MessageTag.BBB_XCV_RFC.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
                assertEquals(MessageTag.BBB_XCV_RFC_ANS.getId(), constraint.getError().getKey());
            } else if (XmlStatus.IGNORED == constraint.getStatus()) {
                // ignore
            } else {
                assertEquals(XmlStatus.OK, constraint.getStatus());
            }
        }
        assertTrue(validTstFound);
        assertTrue(invalidTstFound);

        XmlPSV psv = signatureBBB.getPSV();
        assertEquals(Indication.PASSED, psv.getConclusion().getIndication());

        revocationFreshnessCheckFound = false;
        for (XmlConstraint constraint : psv.getConstraint()) {
            assertEquals(XmlStatus.OK, constraint.getStatus());
            if (MessageTag.BBB_XCV_RFC.getId().equals(constraint.getName().getKey())) {
                revocationFreshnessCheckFound = true;
            }
        }
        assertTrue(revocationFreshnessCheckFound);

        List<eu.europa.esig.dss.detailedreport.jaxb.XmlTimestamp> timestamps = xmlSignature.getTimestamps();
        assertEquals(2, timestamps.size());

        eu.europa.esig.dss.detailedreport.jaxb.XmlTimestamp xmlTimestamp = timestamps.get(0);
        assertEquals(Indication.INDETERMINATE, xmlTimestamp.getConclusion().getIndication());
        assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, xmlTimestamp.getConclusion().getSubIndication());
        assertTrue(checkMessageValuePresence(convert(xmlTimestamp.getConclusion().getErrors()),
                i18nProvider.getMessage(MessageTag.ASCCM_AR_ANS_ANR, DigestAlgorithm.SHA1, MessageTag.ACCM_POS_TST_SIG)));

        XmlValidationProcessBasicTimestamp validationProcessBasicTimestamp = xmlTimestamp.getValidationProcessBasicTimestamp();
        assertEquals(Indication.INDETERMINATE, validationProcessBasicTimestamp.getConclusion().getIndication());
        assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, validationProcessBasicTimestamp.getConclusion().getSubIndication());
        assertTrue(checkMessageValuePresence(convert(validationProcessBasicTimestamp.getConclusion().getErrors()),
                i18nProvider.getMessage(MessageTag.BBB_XCV_ICTIVRSC_ANS)));
        assertTrue(checkMessageValuePresence(convert(validationProcessBasicTimestamp.getConclusion().getErrors()),
                i18nProvider.getMessage(MessageTag.ASCCM_AR_ANS_ANR, DigestAlgorithm.SHA1, MessageTag.ACCM_POS_TST_SIG)));

        XmlValidationProcessArchivalDataTimestamp validationProcessArchivalDataTimestamp = xmlTimestamp.getValidationProcessArchivalDataTimestamp();
        assertEquals(Indication.INDETERMINATE, validationProcessArchivalDataTimestamp.getConclusion().getIndication());
        assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, validationProcessArchivalDataTimestamp.getConclusion().getSubIndication());
        assertTrue(checkMessageValuePresence(convert(validationProcessArchivalDataTimestamp.getConclusion().getErrors()),
                i18nProvider.getMessage(MessageTag.ASCCM_AR_ANS_ANR, DigestAlgorithm.SHA1, MessageTag.ACCM_POS_TST_SIG)));

        boolean basicTstValidationCheckFound = false;
        boolean pastTstValidationCheckFound = false;
        boolean tavCheckFound = false;
        for (XmlConstraint constraint : validationProcessArchivalDataTimestamp.getConstraint()) {
            if (MessageTag.ADEST_IBSVPTC.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.WARNING, constraint.getStatus());
                assertEquals(MessageTag.ADEST_IBSVPTC_ANS.getId(), constraint.getWarning().getKey());
                basicTstValidationCheckFound = true;
            } else if (MessageTag.PSV_IPTVC.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                pastTstValidationCheckFound = true;
            } else if (MessageTag.BBB_TAV_ISVA.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
                assertEquals(MessageTag.BBB_TAV_ISVA_ANS.getId(), constraint.getError().getKey());
                tavCheckFound = true;
            } else {
                assertEquals(XmlStatus.OK, constraint.getStatus());
            }
        }
        assertTrue(basicTstValidationCheckFound);
        assertTrue(pastTstValidationCheckFound);
        assertTrue(tavCheckFound);

        xmlTimestamp = timestamps.get(1);
        assertEquals(Indication.PASSED, xmlTimestamp.getConclusion().getIndication());

        validationProcessBasicTimestamp = xmlTimestamp.getValidationProcessBasicTimestamp();
        assertEquals(Indication.PASSED, validationProcessBasicTimestamp.getConclusion().getIndication());

        validationProcessArchivalDataTimestamp = xmlTimestamp.getValidationProcessArchivalDataTimestamp();
        assertEquals(Indication.PASSED, validationProcessArchivalDataTimestamp.getConclusion().getIndication());

        checkReports(reports);
    }

    @Test
    void dss2730TimestampDelayFailureTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/DSS-2730/dss-2730.xml"));
        assertNotNull(diagnosticData);

        String sigTstId = diagnosticData.getUsedTimestamps().get(0).getId();
        String arcTstId = diagnosticData.getUsedTimestamps().get(1).getId();

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        CertificateConstraints signingCertificateConstraints = validationPolicy
                .getSignatureConstraints().getBasicSignatureConstraints().getSigningCertificate();

        TimeConstraint timeConstraint = new TimeConstraint();
        timeConstraint.setLevel(Level.FAIL);
        timeConstraint.setUnit(TimeUnit.DAYS);
        timeConstraint.setValue(0);
        signingCertificateConstraints.setRevocationFreshness(timeConstraint);

        BasicSignatureConstraints timestampConstrains = validationPolicy.getTimestampConstraints().getBasicSignatureConstraints();
        MultiValuesConstraint multiValuesConstraint = new MultiValuesConstraint();
        multiValuesConstraint.getId().add(TrustServiceStatus.GRANTED.getUri());
        timestampConstrains.setTrustServiceStatus(multiValuesConstraint);

        timeConstraint = new TimeConstraint();
        timeConstraint.setLevel(Level.FAIL);
        timeConstraint.setUnit(TimeUnit.HOURS);
        timeConstraint.setValue(1);
        validationPolicy.getTimestampConstraints().setTimestampDelay(timeConstraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.ADEST_ISTPTDABST_ANS)));
        assertEquals(diagnosticData.getUsedTimestamps().get(1).getProductionTime(),
                simpleReport.getBestSignatureTime(simpleReport.getFirstSignatureId()));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.INDETERMINATE, detailedReport.getFinalIndication(detailedReport.getFirstSignatureId()));
        assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, detailedReport.getFinalSubIndication(detailedReport.getFirstSignatureId()));

        assertEquals(Indication.INDETERMINATE, detailedReport.getBasicValidationIndication(detailedReport.getFirstSignatureId()));
        assertEquals(SubIndication.TRY_LATER, detailedReport.getBasicValidationSubIndication(detailedReport.getFirstSignatureId()));

        eu.europa.esig.dss.detailedreport.jaxb.XmlSignature xmlSignature = detailedReport.getXmlSignatureById(detailedReport.getFirstSignatureId());
        assertNotNull(xmlSignature);

        XmlValidationProcessBasicSignature validationProcessBasicSignature = xmlSignature.getValidationProcessBasicSignature();
        assertEquals(Indication.INDETERMINATE, validationProcessBasicSignature.getConclusion().getIndication());
        assertEquals(SubIndication.TRY_LATER, validationProcessBasicSignature.getConclusion().getSubIndication());
        assertTrue(checkMessageValuePresence(convert(validationProcessBasicSignature.getConclusion().getErrors()),
                i18nProvider.getMessage(MessageTag.BBB_RFC_IRIF_ANS)));

        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertNotNull(signatureBBB);

        XmlXCV xcv = signatureBBB.getXCV();
        assertNotNull(xcv);
        assertEquals(Indication.INDETERMINATE, xcv.getConclusion().getIndication());
        assertEquals(SubIndication.TRY_LATER, xcv.getConclusion().getSubIndication());
        assertTrue(checkMessageValuePresence(convert(xcv.getConclusion().getErrors()),
                i18nProvider.getMessage(MessageTag.BBB_RFC_IRIF_ANS)));

        List<XmlSubXCV> subXCVs = xcv.getSubXCV();
        assertEquals(2, subXCVs.size());

        XmlSubXCV xmlSubXCV = subXCVs.get(0);
        assertEquals(Indication.INDETERMINATE, xmlSubXCV.getConclusion().getIndication());
        assertEquals(SubIndication.TRY_LATER, xmlSubXCV.getConclusion().getSubIndication());

        boolean revocationFreshnessCheckFound = false;
        for (XmlConstraint constraint : xmlSubXCV.getConstraint()) {
            if (MessageTag.BBB_XCV_RFC.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
                assertEquals(MessageTag.BBB_XCV_RFC_ANS.getId(), constraint.getError().getKey());
                revocationFreshnessCheckFound = true;
            } else {
                assertEquals(XmlStatus.OK, constraint.getStatus());
            }
        }
        assertTrue(revocationFreshnessCheckFound);

        XmlValidationProcessLongTermData validationProcessLongTermData = xmlSignature.getValidationProcessLongTermData();
        assertEquals(Indication.INDETERMINATE, validationProcessLongTermData.getConclusion().getIndication());
        assertEquals(SubIndication.TRY_LATER, validationProcessLongTermData.getConclusion().getSubIndication());
        assertTrue(checkMessageValuePresence(convert(validationProcessLongTermData.getConclusion().getErrors()),
                i18nProvider.getMessage(MessageTag.BBB_RFC_IRIF_ANS)));

        boolean basicValidationCheckFound = false;
        revocationFreshnessCheckFound = false;
        for (XmlConstraint constraint : validationProcessLongTermData.getConstraint()) {
            if (MessageTag.ADEST_IBSVPTC.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.WARNING, constraint.getStatus());
                assertEquals(MessageTag.ADEST_IBSVPTC_ANS.getId(), constraint.getWarning().getKey());
                basicValidationCheckFound = true;
            } else if (MessageTag.BBB_XCV_RFC.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
                assertEquals(MessageTag.BBB_XCV_RFC_ANS.getId(), constraint.getError().getKey());
                revocationFreshnessCheckFound = true;
            } else {
                assertEquals(XmlStatus.OK, constraint.getStatus());
            }
        }
        assertTrue(basicValidationCheckFound);
        assertTrue(revocationFreshnessCheckFound);

        XmlValidationProcessArchivalData validationProcessArchivalData = xmlSignature.getValidationProcessArchivalData();
        assertEquals(Indication.INDETERMINATE, validationProcessArchivalData.getConclusion().getIndication());
        assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, validationProcessArchivalData.getConclusion().getSubIndication());
        assertTrue(checkMessageValuePresence(convert(validationProcessArchivalData.getConclusion().getErrors()),
                i18nProvider.getMessage(MessageTag.ADEST_ISTPTDABST_ANS)));

        boolean validTstFound = false;
        boolean invalidTstFound = false;
        boolean psvCheckFound = false;
        boolean tstDelayCheckFound = false;
        for (XmlConstraint constraint : validationProcessArchivalData.getConstraint()) {
            if (MessageTag.ADEST_IBSVPTADC.getId().equals(constraint.getName().getKey())) {
                if (XmlStatus.OK == constraint.getStatus()) {
                    assertEquals(arcTstId, constraint.getId());
                    validTstFound = true;
                } else if (XmlStatus.WARNING == constraint.getStatus()) {
                    assertEquals(sigTstId, constraint.getId());
                    assertEquals(MessageTag.ADEST_IBSVPTADC_ANS.getId(), constraint.getWarning().getKey());
                    invalidTstFound = true;
                }
            } else if (MessageTag.PSV_IPSVC.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                psvCheckFound = true;
            } else if (MessageTag.ADEST_ISTPTDABST.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
                assertEquals(MessageTag.ADEST_ISTPTDABST_ANS.getId(), constraint.getError().getKey());
                tstDelayCheckFound = true;
            } else if (XmlStatus.IGNORED == constraint.getStatus()) {
                // ignore
            } else {
                assertEquals(XmlStatus.OK, constraint.getStatus());
            }
        }
        assertTrue(validTstFound);
        assertTrue(invalidTstFound);
        assertTrue(psvCheckFound);
        assertTrue(tstDelayCheckFound);

        XmlPSV psv = signatureBBB.getPSV();
        assertEquals(Indication.PASSED, psv.getConclusion().getIndication());

        revocationFreshnessCheckFound = false;
        for (XmlConstraint constraint : psv.getConstraint()) {
            assertEquals(XmlStatus.OK, constraint.getStatus());
            if (MessageTag.BBB_XCV_RFC.getId().equals(constraint.getName().getKey())) {
                revocationFreshnessCheckFound = true;
            }
        }
        assertTrue(revocationFreshnessCheckFound);

        List<eu.europa.esig.dss.detailedreport.jaxb.XmlTimestamp> timestamps = xmlSignature.getTimestamps();
        assertEquals(2, timestamps.size());

        eu.europa.esig.dss.detailedreport.jaxb.XmlTimestamp xmlTimestamp = timestamps.get(0);
        assertEquals(Indication.INDETERMINATE, xmlTimestamp.getConclusion().getIndication());
        assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, xmlTimestamp.getConclusion().getSubIndication());
        assertTrue(checkMessageValuePresence(convert(xmlTimestamp.getConclusion().getErrors()),
                i18nProvider.getMessage(MessageTag.ASCCM_AR_ANS_ANR, DigestAlgorithm.SHA1, MessageTag.ACCM_POS_TST_SIG)));

        XmlValidationProcessBasicTimestamp validationProcessBasicTimestamp = xmlTimestamp.getValidationProcessBasicTimestamp();
        assertEquals(Indication.INDETERMINATE, validationProcessBasicTimestamp.getConclusion().getIndication());
        assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, validationProcessBasicTimestamp.getConclusion().getSubIndication());
        assertTrue(checkMessageValuePresence(convert(validationProcessBasicTimestamp.getConclusion().getErrors()),
                i18nProvider.getMessage(MessageTag.BBB_XCV_ICTIVRSC_ANS)));
        assertTrue(checkMessageValuePresence(convert(validationProcessBasicTimestamp.getConclusion().getErrors()),
                i18nProvider.getMessage(MessageTag.ASCCM_AR_ANS_ANR, DigestAlgorithm.SHA1, MessageTag.ACCM_POS_TST_SIG)));

        XmlValidationProcessArchivalDataTimestamp validationProcessArchivalDataTimestamp = xmlTimestamp.getValidationProcessArchivalDataTimestamp();
        assertEquals(Indication.INDETERMINATE, validationProcessArchivalDataTimestamp.getConclusion().getIndication());
        assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, validationProcessArchivalDataTimestamp.getConclusion().getSubIndication());
        assertTrue(checkMessageValuePresence(convert(validationProcessArchivalDataTimestamp.getConclusion().getErrors()),
                i18nProvider.getMessage(MessageTag.ASCCM_AR_ANS_ANR, DigestAlgorithm.SHA1, MessageTag.ACCM_POS_TST_SIG)));

        boolean basicTstValidationCheckFound = false;
        boolean pastTstValidationCheckFound = false;
        boolean tavCheckFound = false;
        for (XmlConstraint constraint : validationProcessArchivalDataTimestamp.getConstraint()) {
            if (MessageTag.ADEST_IBSVPTC.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.WARNING, constraint.getStatus());
                assertEquals(MessageTag.ADEST_IBSVPTC_ANS.getId(), constraint.getWarning().getKey());
                basicTstValidationCheckFound = true;
            } else if (MessageTag.PSV_IPTVC.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                pastTstValidationCheckFound = true;
            } else if (MessageTag.BBB_TAV_ISVA.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
                assertEquals(MessageTag.BBB_TAV_ISVA_ANS.getId(), constraint.getError().getKey());
                tavCheckFound = true;
            } else {
                assertEquals(XmlStatus.OK, constraint.getStatus());
            }
        }
        assertTrue(basicTstValidationCheckFound);
        assertTrue(pastTstValidationCheckFound);
        assertTrue(tavCheckFound);

        xmlTimestamp = timestamps.get(1);
        assertEquals(Indication.PASSED, xmlTimestamp.getConclusion().getIndication());

        validationProcessBasicTimestamp = xmlTimestamp.getValidationProcessBasicTimestamp();
        assertEquals(Indication.PASSED, validationProcessBasicTimestamp.getConclusion().getIndication());

        validationProcessArchivalDataTimestamp = xmlTimestamp.getValidationProcessArchivalDataTimestamp();
        assertEquals(Indication.PASSED, validationProcessArchivalDataTimestamp.getConclusion().getIndication());

        checkReports(reports);
    }

}
