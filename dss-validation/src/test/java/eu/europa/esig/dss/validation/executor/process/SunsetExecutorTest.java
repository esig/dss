package eu.europa.esig.dss.validation.executor.process;

import eu.europa.esig.dss.detailedreport.DetailedReport;
import eu.europa.esig.dss.detailedreport.jaxb.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.detailedreport.jaxb.XmlCRS;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlPCV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlPSV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSignature;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSubXCV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlVTS;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationCertificateQualification;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationSignatureQualification;
import eu.europa.esig.dss.detailedreport.jaxb.XmlXCV;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.DiagnosticDataFacade;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificate;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificateExtension;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificateRevocation;
import eu.europa.esig.dss.diagnostic.jaxb.XmlChainItem;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.diagnostic.jaxb.XmlFoundTimestamp;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTimestamp;
import eu.europa.esig.dss.diagnostic.jaxb.XmlValAssuredShortTermCertificate;
import eu.europa.esig.dss.enumerations.CertificateExtensionEnum;
import eu.europa.esig.dss.enumerations.CertificateQualification;
import eu.europa.esig.dss.enumerations.CertificateSourceType;
import eu.europa.esig.dss.enumerations.CertificateStatus;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.RevocationReason;
import eu.europa.esig.dss.enumerations.SignatureQualification;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.enumerations.ValidationTime;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.ValidationPolicy;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.executor.signature.DefaultSignatureProcessExecutor;
import eu.europa.esig.dss.validation.process.ValidationProcessUtils;
import eu.europa.esig.dss.validation.reports.Reports;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.util.Calendar;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class SunsetExecutorTest extends AbstractProcessExecutorTest {

    @Test
    void validTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_sunset.xml"));
        assertNotNull(xmlDiagnosticData);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();
        assertNotNull(reports);

        DiagnosticData diagnosticData = reports.getDiagnosticData();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId())));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationWarnings(simpleReport.getFirstSignatureId())));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationInfo(simpleReport.getFirstSignatureId())));

        String firstTstId = simpleReport.getSignatureTimestamps(simpleReport.getFirstSignatureId()).get(0).getId();
        assertEquals(Indication.PASSED, simpleReport.getIndication(firstTstId));

        DetailedReport detailedReport = reports.getDetailedReport();
        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertNotNull(signatureBBB);
        assertEquals(Indication.PASSED, signatureBBB.getConclusion().getIndication());

        XmlXCV xcv = signatureBBB.getXCV();
        assertNotNull(xcv);
        assertEquals(Indication.PASSED, xcv.getConclusion().getIndication());
        assertTrue(Utils.isCollectionEmpty(xcv.getConclusion().getErrors()));
        assertTrue(Utils.isCollectionEmpty(xcv.getConclusion().getWarnings()));
        assertTrue(Utils.isCollectionEmpty(xcv.getConclusion().getInfos()));

        int prospectiveChainFoundCounter = 0;
        int trustAnchorSunsetCheckValidCounter = 0;
        int trustAnchorSunsetCheckInvalidCounter = 0;
        int validProspectiveChainFoundCounter = 0;
        int invalidProspectiveChainFoundCounter = 0;
        int xmlSubXCVCheckValidCounter = 0;
        int xmlSubXCVCheckInvalidCounter = 0;

        for (XmlConstraint xmlConstraint : xcv.getConstraint()) {
            if (MessageTag.BBB_XCV_CCCBB.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                ++prospectiveChainFoundCounter;
            } else if (MessageTag.BBB_XCV_IVTBCTSD.getId().equals(xmlConstraint.getName().getKey())) {
                assertNotNull(xmlConstraint.getId());
                assertEquals(i18nProvider.getMessage(MessageTag.CERTIFICATE_SUNSET_DATE,
                                ValidationProcessUtils.getFormattedDate(xmlDiagnosticData.getValidationDate()),
                                ValidationProcessUtils.getFormattedDate(diagnosticData.getCertificateById(xmlConstraint.getId()).getTrustSunsetDate())),
                        xmlConstraint.getAdditionalInfo());
                if (XmlStatus.OK == xmlConstraint.getStatus()) {
                    ++trustAnchorSunsetCheckValidCounter;
                } else if (XmlStatus.WARNING == xmlConstraint.getStatus()) {
                    assertEquals(MessageTag.BBB_XCV_IVTBCTSD_ANS.getId(), xmlConstraint.getWarning().getKey());
                    ++trustAnchorSunsetCheckInvalidCounter;
                }
            } else if (MessageTag.BBB_XCV_HPCCVVT.getId().equals(xmlConstraint.getName().getKey())) {
                if (XmlStatus.OK == xmlConstraint.getStatus()) {
                    ++validProspectiveChainFoundCounter;
                } else if (XmlStatus.NOT_OK == xmlConstraint.getStatus()) {
                    assertEquals(MessageTag.BBB_XCV_HPCCVVT_ANS.getId(), xmlConstraint.getError().getKey());
                    ++ invalidProspectiveChainFoundCounter;
                }
            } else if (MessageTag.BBB_XCV_SUB.getId().equals(xmlConstraint.getName().getKey())) {
                assertNotNull(xmlConstraint.getId());
                if (XmlStatus.OK == xmlConstraint.getStatus()) {
                    ++xmlSubXCVCheckValidCounter;
                } else if (XmlStatus.NOT_OK == xmlConstraint.getStatus()) {
                    assertEquals(MessageTag.BBB_XCV_SUB_ANS.getId(), xmlConstraint.getError().getKey());
                    ++xmlSubXCVCheckInvalidCounter;
                }
            }
        }

        assertEquals(1, prospectiveChainFoundCounter);
        assertEquals(1, trustAnchorSunsetCheckValidCounter);
        assertEquals(0, trustAnchorSunsetCheckInvalidCounter);
        assertEquals(1, validProspectiveChainFoundCounter);
        assertEquals(0, invalidProspectiveChainFoundCounter);
        assertEquals(3, xmlSubXCVCheckValidCounter);
        assertEquals(0, xmlSubXCVCheckInvalidCounter);

        List<XmlSubXCV> subXCVs = xcv.getSubXCV();
        assertEquals(3, subXCVs.size());

        int untrustedCertCounter = 0;
        int trustedCertCounter = 0;
        for (XmlSubXCV subXCV : subXCVs) {
            if (subXCV.isTrustAnchor()) {
                assertEquals(1, subXCV.getConstraint().size());
                assertEquals(MessageTag.BBB_XCV_IVTBCTSD.getId(), subXCV.getConstraint().get(0).getName().getKey());
                assertEquals(XmlStatus.OK, subXCV.getConstraint().get(0).getStatus());
                assertEquals(i18nProvider.getMessage(MessageTag.CERTIFICATE_SUNSET_DATE,
                        ValidationProcessUtils.getFormattedDate(xmlDiagnosticData.getValidationDate()),
                        ValidationProcessUtils.getFormattedDate(diagnosticData.getCertificateById(subXCV.getId()).getTrustSunsetDate())),
                        subXCV.getConstraint().get(0).getAdditionalInfo());
                ++trustedCertCounter;
            } else {
                ++untrustedCertCounter;
            }
        }
        assertEquals(2, untrustedCertCounter);
        assertEquals(1, trustedCertCounter);

        boolean signatureTstFound = false;
        boolean archiveTstFound = false;
        for (String timestampId : diagnosticData.getTimestampIdList()) {
            XmlBasicBuildingBlocks timestampBBB = detailedReport.getBasicBuildingBlockById(timestampId);

            xcv = timestampBBB.getXCV();
            assertNotNull(xcv);
            assertEquals(Indication.PASSED, xcv.getConclusion().getIndication());

            subXCVs = xcv.getSubXCV();
            if (subXCVs.size() == 2) {
                signatureTstFound = true;
            } else if (subXCVs.size() == 1) {
                archiveTstFound = true;
            }

            untrustedCertCounter = 0;
            trustedCertCounter = 0;
            for (XmlSubXCV subXCV : subXCVs) {
                if (subXCV.isTrustAnchor()) {
                    assertEquals(1, subXCV.getConstraint().size());
                    assertEquals(MessageTag.BBB_XCV_IVTBCTSD.getId(), subXCV.getConstraint().get(0).getName().getKey());
                    assertEquals(XmlStatus.OK, subXCV.getConstraint().get(0).getStatus());
                    assertEquals(i18nProvider.getMessage(MessageTag.CERTIFICATE_SUNSET_DATE,
                                    ValidationProcessUtils.getFormattedDate(xmlDiagnosticData.getValidationDate()),
                                    ValidationProcessUtils.getFormattedDate(diagnosticData.getCertificateById(subXCV.getId()).getTrustSunsetDate())),
                            subXCV.getConstraint().get(0).getAdditionalInfo());
                    ++trustedCertCounter;
                } else {
                    ++untrustedCertCounter;
                }
            }
            assertEquals(subXCVs.size() - 1, untrustedCertCounter);
            assertEquals(1, trustedCertCounter);

        }
        assertTrue(signatureTstFound);
        assertTrue(archiveTstFound);

        validateBestSigningTimes(reports);
        checkReports(reports);
    }

    @Test
    void expiredSigTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_sunset.xml"));
        assertNotNull(xmlDiagnosticData);

        Calendar calendar = Calendar.getInstance();
        calendar.set(2023, Calendar.JANUARY, 0, 0, 0, 0);
        Date validationTime = calendar.getTime();

        xmlDiagnosticData.setValidationDate(validationTime);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();
        assertNotNull(reports);

        DiagnosticData diagnosticData = reports.getDiagnosticData();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId())));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationWarnings(simpleReport.getFirstSignatureId())));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationInfo(simpleReport.getFirstSignatureId())));

        String firstTstId = simpleReport.getSignatureTimestamps(simpleReport.getFirstSignatureId()).get(0).getId();
        assertEquals(Indication.PASSED, simpleReport.getIndication(firstTstId));

        DetailedReport detailedReport = reports.getDetailedReport();
        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertNotNull(signatureBBB);
        assertEquals(Indication.PASSED, signatureBBB.getConclusion().getIndication());

        XmlXCV xcv = signatureBBB.getXCV();
        assertNotNull(xcv);
        assertEquals(Indication.INDETERMINATE, xcv.getConclusion().getIndication());
        assertEquals(SubIndication.NO_CERTIFICATE_CHAIN_FOUND_NO_POE, xcv.getConclusion().getSubIndication());
        assertTrue(checkMessageValuePresence(convert(xcv.getConclusion().getErrors()), i18nProvider.getMessage(MessageTag.BBB_XCV_ICTIVRSC_ANS)));
        assertTrue(checkMessageValuePresence(convert(xcv.getConclusion().getErrors()), i18nProvider.getMessage(MessageTag.BBB_XCV_HPCCVVT_ANS)));

        int prospectiveChainFoundCounter = 0;
        int trustAnchorSunsetCheckValidCounter = 0;
        int trustAnchorSunsetCheckInvalidCounter = 0;
        int validProspectiveChainFoundCounter = 0;
        int invalidProspectiveChainFoundCounter = 0;
        int xmlSubXCVCheckValidCounter = 0;
        int xmlSubXCVCheckInvalidCounter = 0;

        for (XmlConstraint xmlConstraint : xcv.getConstraint()) {
            if (MessageTag.BBB_XCV_CCCBB.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                ++prospectiveChainFoundCounter;
            } else if (MessageTag.BBB_XCV_IVTBCTSD.getId().equals(xmlConstraint.getName().getKey())) {
                assertNotNull(xmlConstraint.getId());
                assertEquals(i18nProvider.getMessage(MessageTag.CERTIFICATE_SUNSET_DATE,
                                ValidationProcessUtils.getFormattedDate(xmlDiagnosticData.getValidationDate()),
                                ValidationProcessUtils.getFormattedDate(diagnosticData.getCertificateById(xmlConstraint.getId()).getTrustSunsetDate())),
                        xmlConstraint.getAdditionalInfo());
                if (XmlStatus.OK == xmlConstraint.getStatus()) {
                    ++trustAnchorSunsetCheckValidCounter;
                } else if (XmlStatus.WARNING == xmlConstraint.getStatus()) {
                    assertEquals(MessageTag.BBB_XCV_IVTBCTSD_ANS.getId(), xmlConstraint.getWarning().getKey());
                    ++trustAnchorSunsetCheckInvalidCounter;
                }
            } else if (MessageTag.BBB_XCV_HPCCVVT.getId().equals(xmlConstraint.getName().getKey())) {
                if (XmlStatus.OK == xmlConstraint.getStatus()) {
                    ++validProspectiveChainFoundCounter;
                } else if (XmlStatus.NOT_OK == xmlConstraint.getStatus()) {
                    assertEquals(MessageTag.BBB_XCV_HPCCVVT_ANS.getId(), xmlConstraint.getError().getKey());
                    ++ invalidProspectiveChainFoundCounter;
                }
            } else if (MessageTag.BBB_XCV_SUB.getId().equals(xmlConstraint.getName().getKey())) {
                assertNotNull(xmlConstraint.getId());
                if (XmlStatus.OK == xmlConstraint.getStatus()) {
                    ++xmlSubXCVCheckValidCounter;
                } else if (XmlStatus.NOT_OK == xmlConstraint.getStatus()) {
                    assertEquals(MessageTag.BBB_XCV_SUB_ANS.getId(), xmlConstraint.getError().getKey());
                    ++xmlSubXCVCheckInvalidCounter;
                }
            }
        }

        assertEquals(1, prospectiveChainFoundCounter);
        assertEquals(0, trustAnchorSunsetCheckValidCounter);
        assertEquals(1, trustAnchorSunsetCheckInvalidCounter);
        assertEquals(0, validProspectiveChainFoundCounter);
        assertEquals(1, invalidProspectiveChainFoundCounter);
        assertEquals(0, xmlSubXCVCheckValidCounter);
        assertEquals(0, xmlSubXCVCheckInvalidCounter);

        List<XmlSubXCV> subXCVs = xcv.getSubXCV();
        assertEquals(3, subXCVs.size());

        int untrustedCertCounter = 0;
        int trustedCertCounter = 0;
        for (XmlSubXCV subXCV : subXCVs) {
            if (subXCV.isTrustAnchor()) {
                assertEquals(Indication.INDETERMINATE, subXCV.getConclusion().getIndication());
                assertEquals(SubIndication.NO_CERTIFICATE_CHAIN_FOUND_NO_POE, subXCV.getConclusion().getSubIndication());
                assertTrue(checkMessageValuePresence(convert(subXCV.getConclusion().getErrors()), i18nProvider.getMessage(MessageTag.BBB_XCV_IOTAA_ANS)));
                assertTrue(checkMessageValuePresence(convert(subXCV.getConclusion().getWarnings()), i18nProvider.getMessage(MessageTag.BBB_XCV_IVTBCTSD_ANS)));

                boolean validationTimeCheckFound = false;
                boolean validProspectiveChainCheckFound = false;
                for (XmlConstraint xmlConstraint : subXCV.getConstraint()) {
                    if (MessageTag.BBB_XCV_IVTBCTSD.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.WARNING, xmlConstraint.getStatus());
                        assertEquals(MessageTag.BBB_XCV_IVTBCTSD_ANS.getId(), xmlConstraint.getWarning().getKey());
                        assertEquals(i18nProvider.getMessage(MessageTag.CERTIFICATE_SUNSET_DATE,
                                ValidationProcessUtils.getFormattedDate(xmlDiagnosticData.getValidationDate()),
                                ValidationProcessUtils.getFormattedDate(diagnosticData.getCertificateById(subXCV.getId()).getTrustSunsetDate())), xmlConstraint.getAdditionalInfo());
                        validationTimeCheckFound = true;
                    } else if (MessageTag.BBB_XCV_IOTAA.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                        assertEquals(MessageTag.BBB_XCV_IOTAA_ANS.getId(), xmlConstraint.getError().getKey());
                        validProspectiveChainCheckFound = true;
                    }
                }
                assertTrue(validationTimeCheckFound);
                assertTrue(validProspectiveChainCheckFound);
                ++trustedCertCounter;
            } else {
                ++untrustedCertCounter;
            }
        }
        assertEquals(2, untrustedCertCounter);
        assertEquals(1, trustedCertCounter);

        boolean signatureTstFound = false;
        boolean archiveTstFound = false;
        for (String timestampId : diagnosticData.getTimestampIdList()) {
            XmlBasicBuildingBlocks timestampBBB = detailedReport.getBasicBuildingBlockById(timestampId);

            xcv = timestampBBB.getXCV();
            assertNotNull(xcv);

            subXCVs = xcv.getSubXCV();
            if (subXCVs.size() == 2) {
                assertEquals(Indication.INDETERMINATE, xcv.getConclusion().getIndication());
                assertEquals(SubIndication.NO_CERTIFICATE_CHAIN_FOUND_NO_POE, xcv.getConclusion().getSubIndication());
                assertTrue(checkMessageValuePresence(convert(xcv.getConclusion().getErrors()), i18nProvider.getMessage(MessageTag.BBB_XCV_ICTIVRSC_ANS)));
                assertTrue(checkMessageValuePresence(convert(xcv.getConclusion().getErrors()), i18nProvider.getMessage(MessageTag.BBB_XCV_HPCCVVT_ANS)));
                signatureTstFound = true;
            } else if (subXCVs.size() == 1) {
                assertEquals(Indication.PASSED, xcv.getConclusion().getIndication());
                archiveTstFound = true;
            }

            untrustedCertCounter = 0;
            trustedCertCounter = 0;
            for (XmlSubXCV subXCV : subXCVs) {
                if (subXCV.isTrustAnchor()) {
                    if (subXCVs.size() == 2) {
                        // sig tst
                        assertEquals(Indication.INDETERMINATE, subXCV.getConclusion().getIndication());
                        assertEquals(SubIndication.NO_CERTIFICATE_CHAIN_FOUND_NO_POE, subXCV.getConclusion().getSubIndication());
                        assertTrue(checkMessageValuePresence(convert(subXCV.getConclusion().getErrors()), i18nProvider.getMessage(MessageTag.BBB_XCV_IOTAA_ANS)));
                        assertTrue(checkMessageValuePresence(convert(subXCV.getConclusion().getWarnings()), i18nProvider.getMessage(MessageTag.BBB_XCV_IVTBCTSD_ANS)));

                        boolean validationTimeCheckFound = false;
                        boolean validProspectiveChainCheckFound = false;
                        for (XmlConstraint xmlConstraint : subXCV.getConstraint()) {
                            if (MessageTag.BBB_XCV_IVTBCTSD.getId().equals(xmlConstraint.getName().getKey())) {
                                assertEquals(XmlStatus.WARNING, xmlConstraint.getStatus());
                                assertEquals(MessageTag.BBB_XCV_IVTBCTSD_ANS.getId(), xmlConstraint.getWarning().getKey());
                                assertEquals(i18nProvider.getMessage(MessageTag.CERTIFICATE_SUNSET_DATE,
                                        ValidationProcessUtils.getFormattedDate(xmlDiagnosticData.getValidationDate()),
                                        ValidationProcessUtils.getFormattedDate(diagnosticData.getCertificateById(subXCV.getId()).getTrustSunsetDate())), xmlConstraint.getAdditionalInfo());
                                validationTimeCheckFound = true;
                            } else if (MessageTag.BBB_XCV_IOTAA.getId().equals(xmlConstraint.getName().getKey())) {
                                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                                assertEquals(MessageTag.BBB_XCV_IOTAA_ANS.getId(), xmlConstraint.getError().getKey());
                                validProspectiveChainCheckFound = true;
                            }
                        }
                        assertTrue(validationTimeCheckFound);
                        assertTrue(validProspectiveChainCheckFound);
                    } else {
                        // arc tst
                        assertEquals(Indication.PASSED, subXCV.getConclusion().getIndication());

                        boolean validationTimeCheckFound = false;
                        boolean validProspectiveChainCheckFound = false;
                        for (XmlConstraint xmlConstraint : subXCV.getConstraint()) {
                            if (MessageTag.BBB_XCV_IVTBCTSD.getId().equals(xmlConstraint.getName().getKey())) {
                                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                                assertEquals(i18nProvider.getMessage(MessageTag.CERTIFICATE_SUNSET_DATE,
                                        ValidationProcessUtils.getFormattedDate(xmlDiagnosticData.getValidationDate()),
                                        ValidationProcessUtils.getFormattedDate(diagnosticData.getCertificateById(subXCV.getId()).getTrustSunsetDate())), xmlConstraint.getAdditionalInfo());
                                validationTimeCheckFound = true;
                            } else if (MessageTag.BBB_XCV_IOTAA.getId().equals(xmlConstraint.getName().getKey())) {
                                validProspectiveChainCheckFound = true;
                            }
                        }
                        assertTrue(validationTimeCheckFound);
                        assertFalse(validProspectiveChainCheckFound);
                    }
                    ++trustedCertCounter;
                } else {
                    ++untrustedCertCounter;
                }
            }
            assertEquals(subXCVs.size() - 1, untrustedCertCounter);
            assertEquals(1, trustedCertCounter);

        }
        assertTrue(signatureTstFound);
        assertTrue(archiveTstFound);

        validateBestSigningTimes(reports);
        checkReports(reports);
    }

    @Test
    void expiredSigSunsetDateTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_sunset.xml"));
        assertNotNull(xmlDiagnosticData);

        Calendar calendar = Calendar.getInstance();
        calendar.set(2022, Calendar.FEBRUARY, 1, 0, 0, 0);
        Date validationTime = calendar.getTime();

        xmlDiagnosticData.setValidationDate(validationTime);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();
        assertNotNull(reports);

        DiagnosticData diagnosticData = reports.getDiagnosticData();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId())));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationWarnings(simpleReport.getFirstSignatureId())));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationInfo(simpleReport.getFirstSignatureId())));

        String firstTstId = simpleReport.getSignatureTimestamps(simpleReport.getFirstSignatureId()).get(0).getId();
        assertEquals(Indication.PASSED, simpleReport.getIndication(firstTstId));

        DetailedReport detailedReport = reports.getDetailedReport();
        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertNotNull(signatureBBB);
        assertEquals(Indication.PASSED, signatureBBB.getConclusion().getIndication());

        XmlXCV xcv = signatureBBB.getXCV();
        assertNotNull(xcv);
        assertEquals(Indication.INDETERMINATE, xcv.getConclusion().getIndication());
        assertEquals(SubIndication.NO_CERTIFICATE_CHAIN_FOUND_NO_POE, xcv.getConclusion().getSubIndication());
        assertTrue(checkMessageValuePresence(convert(xcv.getConclusion().getErrors()), i18nProvider.getMessage(MessageTag.BBB_XCV_HPCCVVT_ANS)));

        int prospectiveChainFoundCounter = 0;
        int trustAnchorSunsetCheckValidCounter = 0;
        int trustAnchorSunsetCheckInvalidCounter = 0;
        int validProspectiveChainFoundCounter = 0;
        int invalidProspectiveChainFoundCounter = 0;
        int xmlSubXCVCheckValidCounter = 0;
        int xmlSubXCVCheckInvalidCounter = 0;

        for (XmlConstraint xmlConstraint : xcv.getConstraint()) {
            if (MessageTag.BBB_XCV_CCCBB.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                ++prospectiveChainFoundCounter;
            } else if (MessageTag.BBB_XCV_IVTBCTSD.getId().equals(xmlConstraint.getName().getKey())) {
                assertNotNull(xmlConstraint.getId());
                assertEquals(i18nProvider.getMessage(MessageTag.CERTIFICATE_SUNSET_DATE,
                                ValidationProcessUtils.getFormattedDate(xmlDiagnosticData.getValidationDate()),
                                ValidationProcessUtils.getFormattedDate(diagnosticData.getCertificateById(xmlConstraint.getId()).getTrustSunsetDate())),
                        xmlConstraint.getAdditionalInfo());
                if (XmlStatus.OK == xmlConstraint.getStatus()) {
                    ++trustAnchorSunsetCheckValidCounter;
                } else if (XmlStatus.WARNING == xmlConstraint.getStatus()) {
                    assertEquals(MessageTag.BBB_XCV_IVTBCTSD_ANS.getId(), xmlConstraint.getWarning().getKey());
                    ++trustAnchorSunsetCheckInvalidCounter;
                }
            } else if (MessageTag.BBB_XCV_HPCCVVT.getId().equals(xmlConstraint.getName().getKey())) {
                if (XmlStatus.OK == xmlConstraint.getStatus()) {
                    ++validProspectiveChainFoundCounter;
                } else if (XmlStatus.NOT_OK == xmlConstraint.getStatus()) {
                    assertEquals(MessageTag.BBB_XCV_HPCCVVT_ANS.getId(), xmlConstraint.getError().getKey());
                    ++ invalidProspectiveChainFoundCounter;
                }
            } else if (MessageTag.BBB_XCV_SUB.getId().equals(xmlConstraint.getName().getKey())) {
                assertNotNull(xmlConstraint.getId());
                if (XmlStatus.OK == xmlConstraint.getStatus()) {
                    ++xmlSubXCVCheckValidCounter;
                } else if (XmlStatus.NOT_OK == xmlConstraint.getStatus()) {
                    assertEquals(MessageTag.BBB_XCV_SUB_ANS.getId(), xmlConstraint.getError().getKey());
                    ++xmlSubXCVCheckInvalidCounter;
                }
            }
        }

        assertEquals(1, prospectiveChainFoundCounter);
        assertEquals(0, trustAnchorSunsetCheckValidCounter);
        assertEquals(1, trustAnchorSunsetCheckInvalidCounter);
        assertEquals(0, validProspectiveChainFoundCounter);
        assertEquals(1, invalidProspectiveChainFoundCounter);
        assertEquals(0, xmlSubXCVCheckValidCounter);
        assertEquals(0, xmlSubXCVCheckInvalidCounter);

        List<XmlSubXCV> subXCVs = xcv.getSubXCV();
        assertEquals(3, subXCVs.size());

        int untrustedCertCounter = 0;
        int trustedCertCounter = 0;
        for (XmlSubXCV subXCV : subXCVs) {
            if (subXCV.isTrustAnchor()) {
                assertEquals(Indication.INDETERMINATE, subXCV.getConclusion().getIndication());
                assertEquals(SubIndication.NO_CERTIFICATE_CHAIN_FOUND_NO_POE, subXCV.getConclusion().getSubIndication());
                assertTrue(checkMessageValuePresence(convert(subXCV.getConclusion().getErrors()), i18nProvider.getMessage(MessageTag.BBB_XCV_IOTAA_ANS)));
                assertTrue(checkMessageValuePresence(convert(subXCV.getConclusion().getWarnings()), i18nProvider.getMessage(MessageTag.BBB_XCV_IVTBCTSD_ANS)));

                boolean validationTimeCheckFound = false;
                boolean validProspectiveChainCheckFound = false;
                for (XmlConstraint xmlConstraint : subXCV.getConstraint()) {
                    if (MessageTag.BBB_XCV_IVTBCTSD.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.WARNING, xmlConstraint.getStatus());
                        assertEquals(MessageTag.BBB_XCV_IVTBCTSD_ANS.getId(), xmlConstraint.getWarning().getKey());
                        assertEquals(i18nProvider.getMessage(MessageTag.CERTIFICATE_SUNSET_DATE,
                                ValidationProcessUtils.getFormattedDate(xmlDiagnosticData.getValidationDate()),
                                ValidationProcessUtils.getFormattedDate(diagnosticData.getCertificateById(subXCV.getId()).getTrustSunsetDate())), xmlConstraint.getAdditionalInfo());
                        validationTimeCheckFound = true;
                    } else if (MessageTag.BBB_XCV_IOTAA.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                        assertEquals(MessageTag.BBB_XCV_IOTAA_ANS.getId(), xmlConstraint.getError().getKey());
                        validProspectiveChainCheckFound = true;
                    }
                }
                assertTrue(validationTimeCheckFound);
                assertTrue(validProspectiveChainCheckFound);
                ++trustedCertCounter;
            } else {
                ++untrustedCertCounter;
            }
        }
        assertEquals(2, untrustedCertCounter);
        assertEquals(1, trustedCertCounter);

        boolean signatureTstFound = false;
        boolean archiveTstFound = false;
        for (String timestampId : diagnosticData.getTimestampIdList()) {
            XmlBasicBuildingBlocks timestampBBB = detailedReport.getBasicBuildingBlockById(timestampId);

            xcv = timestampBBB.getXCV();
            assertNotNull(xcv);

            subXCVs = xcv.getSubXCV();
            if (subXCVs.size() == 2) {
                assertEquals(Indication.INDETERMINATE, xcv.getConclusion().getIndication());
                assertEquals(SubIndication.NO_CERTIFICATE_CHAIN_FOUND_NO_POE, xcv.getConclusion().getSubIndication());
                assertTrue(checkMessageValuePresence(convert(xcv.getConclusion().getErrors()), i18nProvider.getMessage(MessageTag.BBB_XCV_HPCCVVT_ANS)));
                signatureTstFound = true;
            } else if (subXCVs.size() == 1) {
                assertEquals(Indication.PASSED, xcv.getConclusion().getIndication());
                archiveTstFound = true;
            }

            untrustedCertCounter = 0;
            trustedCertCounter = 0;
            for (XmlSubXCV subXCV : subXCVs) {
                if (subXCV.isTrustAnchor()) {
                    if (subXCVs.size() == 2) {
                        // sig tst
                        assertEquals(Indication.INDETERMINATE, subXCV.getConclusion().getIndication());
                        assertEquals(SubIndication.NO_CERTIFICATE_CHAIN_FOUND_NO_POE, subXCV.getConclusion().getSubIndication());
                        assertTrue(checkMessageValuePresence(convert(subXCV.getConclusion().getErrors()), i18nProvider.getMessage(MessageTag.BBB_XCV_IOTAA_ANS)));
                        assertTrue(checkMessageValuePresence(convert(subXCV.getConclusion().getWarnings()), i18nProvider.getMessage(MessageTag.BBB_XCV_IVTBCTSD_ANS)));

                        boolean validationTimeCheckFound = false;
                        boolean validProspectiveChainCheckFound = false;
                        for (XmlConstraint xmlConstraint : subXCV.getConstraint()) {
                            if (MessageTag.BBB_XCV_IVTBCTSD.getId().equals(xmlConstraint.getName().getKey())) {
                                assertEquals(XmlStatus.WARNING, xmlConstraint.getStatus());
                                assertEquals(MessageTag.BBB_XCV_IVTBCTSD_ANS.getId(), xmlConstraint.getWarning().getKey());
                                assertEquals(i18nProvider.getMessage(MessageTag.CERTIFICATE_SUNSET_DATE,
                                        ValidationProcessUtils.getFormattedDate(xmlDiagnosticData.getValidationDate()),
                                        ValidationProcessUtils.getFormattedDate(diagnosticData.getCertificateById(subXCV.getId()).getTrustSunsetDate())), xmlConstraint.getAdditionalInfo());
                                validationTimeCheckFound = true;
                            } else if (MessageTag.BBB_XCV_IOTAA.getId().equals(xmlConstraint.getName().getKey())) {
                                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                                assertEquals(MessageTag.BBB_XCV_IOTAA_ANS.getId(), xmlConstraint.getError().getKey());
                                validProspectiveChainCheckFound = true;
                            }
                        }
                        assertTrue(validationTimeCheckFound);
                        assertTrue(validProspectiveChainCheckFound);
                    } else {
                        // arc tst
                        assertEquals(Indication.PASSED, subXCV.getConclusion().getIndication());

                        boolean validationTimeCheckFound = false;
                        boolean validProspectiveChainCheckFound = false;
                        for (XmlConstraint xmlConstraint : subXCV.getConstraint()) {
                            if (MessageTag.BBB_XCV_IVTBCTSD.getId().equals(xmlConstraint.getName().getKey())) {
                                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                                assertEquals(i18nProvider.getMessage(MessageTag.CERTIFICATE_SUNSET_DATE,
                                        ValidationProcessUtils.getFormattedDate(xmlDiagnosticData.getValidationDate()),
                                        ValidationProcessUtils.getFormattedDate(diagnosticData.getCertificateById(subXCV.getId()).getTrustSunsetDate())), xmlConstraint.getAdditionalInfo());
                                validationTimeCheckFound = true;
                            } else if (MessageTag.BBB_XCV_IOTAA.getId().equals(xmlConstraint.getName().getKey())) {
                                validProspectiveChainCheckFound = true;
                            }
                        }
                        assertTrue(validationTimeCheckFound);
                        assertFalse(validProspectiveChainCheckFound);
                    }
                    ++trustedCertCounter;
                } else {
                    ++untrustedCertCounter;
                }
            }
            assertEquals(subXCVs.size() - 1, untrustedCertCounter);
            assertEquals(1, trustedCertCounter);

        }
        assertTrue(signatureTstFound);
        assertTrue(archiveTstFound);

        validateBestSigningTimes(reports);
        checkReports(reports);
    }

    @Test
    void expiredSigSunsetDateNoArcTstTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_sunset.xml"));
        assertNotNull(xmlDiagnosticData);

        Calendar calendar = Calendar.getInstance();
        calendar.set(2022, Calendar.FEBRUARY, 1, 0, 0, 0);
        Date validationTime = calendar.getTime();

        xmlDiagnosticData.setValidationDate(validationTime);

        List<XmlFoundTimestamp> foundTimestamps = xmlDiagnosticData.getSignatures().get(0).getFoundTimestamps();
        foundTimestamps.remove(foundTimestamps.get(1));

        List<XmlTimestamp> usedTimestamps = xmlDiagnosticData.getUsedTimestamps();
        usedTimestamps.remove(usedTimestamps.get(1));

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();
        assertNotNull(reports);

        DiagnosticData diagnosticData = reports.getDiagnosticData();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.NO_CERTIFICATE_CHAIN_FOUND_NO_POE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_XCV_HPCCVVT_ANS)));

        String firstTstId = simpleReport.getSignatureTimestamps(simpleReport.getFirstSignatureId()).get(0).getId();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(firstTstId));
        assertEquals(SubIndication.NO_CERTIFICATE_CHAIN_FOUND_NO_POE, simpleReport.getSubIndication(firstTstId));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(firstTstId),
                i18nProvider.getMessage(MessageTag.BBB_XCV_HPCCVVT_ANS)));

        DetailedReport detailedReport = reports.getDetailedReport();
        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertNotNull(signatureBBB);
        assertEquals(Indication.INDETERMINATE, signatureBBB.getConclusion().getIndication());
        assertEquals(SubIndication.NO_CERTIFICATE_CHAIN_FOUND_NO_POE, signatureBBB.getConclusion().getSubIndication());

        XmlXCV xcv = signatureBBB.getXCV();
        assertNotNull(xcv);
        assertEquals(Indication.INDETERMINATE, xcv.getConclusion().getIndication());
        assertEquals(SubIndication.NO_CERTIFICATE_CHAIN_FOUND_NO_POE, xcv.getConclusion().getSubIndication());
        assertTrue(checkMessageValuePresence(convert(xcv.getConclusion().getErrors()), i18nProvider.getMessage(MessageTag.BBB_XCV_HPCCVVT_ANS)));

        int prospectiveChainFoundCounter = 0;
        int trustAnchorSunsetCheckValidCounter = 0;
        int trustAnchorSunsetCheckInvalidCounter = 0;
        int validProspectiveChainFoundCounter = 0;
        int invalidProspectiveChainFoundCounter = 0;
        int xmlSubXCVCheckValidCounter = 0;
        int xmlSubXCVCheckInvalidCounter = 0;

        for (XmlConstraint xmlConstraint : xcv.getConstraint()) {
            if (MessageTag.BBB_XCV_CCCBB.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                ++prospectiveChainFoundCounter;
            } else if (MessageTag.BBB_XCV_IVTBCTSD.getId().equals(xmlConstraint.getName().getKey())) {
                assertNotNull(xmlConstraint.getId());
                assertEquals(i18nProvider.getMessage(MessageTag.CERTIFICATE_SUNSET_DATE,
                                ValidationProcessUtils.getFormattedDate(xmlDiagnosticData.getValidationDate()),
                                ValidationProcessUtils.getFormattedDate(diagnosticData.getCertificateById(xmlConstraint.getId()).getTrustSunsetDate())),
                        xmlConstraint.getAdditionalInfo());
                if (XmlStatus.OK == xmlConstraint.getStatus()) {
                    ++trustAnchorSunsetCheckValidCounter;
                } else if (XmlStatus.WARNING == xmlConstraint.getStatus()) {
                    assertEquals(MessageTag.BBB_XCV_IVTBCTSD_ANS.getId(), xmlConstraint.getWarning().getKey());
                    ++trustAnchorSunsetCheckInvalidCounter;
                }
            } else if (MessageTag.BBB_XCV_HPCCVVT.getId().equals(xmlConstraint.getName().getKey())) {
                if (XmlStatus.OK == xmlConstraint.getStatus()) {
                    ++validProspectiveChainFoundCounter;
                } else if (XmlStatus.NOT_OK == xmlConstraint.getStatus()) {
                    assertEquals(MessageTag.BBB_XCV_HPCCVVT_ANS.getId(), xmlConstraint.getError().getKey());
                    ++ invalidProspectiveChainFoundCounter;
                }
            } else if (MessageTag.BBB_XCV_SUB.getId().equals(xmlConstraint.getName().getKey())) {
                assertNotNull(xmlConstraint.getId());
                if (XmlStatus.OK == xmlConstraint.getStatus()) {
                    ++xmlSubXCVCheckValidCounter;
                } else if (XmlStatus.NOT_OK == xmlConstraint.getStatus()) {
                    assertEquals(MessageTag.BBB_XCV_SUB_ANS.getId(), xmlConstraint.getError().getKey());
                    ++xmlSubXCVCheckInvalidCounter;
                }
            }
        }

        assertEquals(1, prospectiveChainFoundCounter);
        assertEquals(0, trustAnchorSunsetCheckValidCounter);
        assertEquals(1, trustAnchorSunsetCheckInvalidCounter);
        assertEquals(0, validProspectiveChainFoundCounter);
        assertEquals(1, invalidProspectiveChainFoundCounter);
        assertEquals(0, xmlSubXCVCheckValidCounter);
        assertEquals(0, xmlSubXCVCheckInvalidCounter);

        List<XmlSubXCV> subXCVs = xcv.getSubXCV();
        assertEquals(3, subXCVs.size());

        int untrustedCertCounter = 0;
        int trustedCertCounter = 0;
        for (XmlSubXCV subXCV : subXCVs) {
            if (subXCV.isTrustAnchor()) {
                assertEquals(Indication.INDETERMINATE, subXCV.getConclusion().getIndication());
                assertEquals(SubIndication.NO_CERTIFICATE_CHAIN_FOUND_NO_POE, subXCV.getConclusion().getSubIndication());
                assertTrue(checkMessageValuePresence(convert(subXCV.getConclusion().getErrors()), i18nProvider.getMessage(MessageTag.BBB_XCV_IOTAA_ANS)));
                assertTrue(checkMessageValuePresence(convert(subXCV.getConclusion().getWarnings()), i18nProvider.getMessage(MessageTag.BBB_XCV_IVTBCTSD_ANS)));

                boolean validationTimeCheckFound = false;
                boolean validProspectiveChainCheckFound = false;
                for (XmlConstraint xmlConstraint : subXCV.getConstraint()) {
                    if (MessageTag.BBB_XCV_IVTBCTSD.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.WARNING, xmlConstraint.getStatus());
                        assertEquals(MessageTag.BBB_XCV_IVTBCTSD_ANS.getId(), xmlConstraint.getWarning().getKey());
                        assertEquals(i18nProvider.getMessage(MessageTag.CERTIFICATE_SUNSET_DATE,
                                ValidationProcessUtils.getFormattedDate(xmlDiagnosticData.getValidationDate()),
                                ValidationProcessUtils.getFormattedDate(diagnosticData.getCertificateById(subXCV.getId()).getTrustSunsetDate())), xmlConstraint.getAdditionalInfo());
                        validationTimeCheckFound = true;
                    } else if (MessageTag.BBB_XCV_IOTAA.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                        assertEquals(MessageTag.BBB_XCV_IOTAA_ANS.getId(), xmlConstraint.getError().getKey());
                        validProspectiveChainCheckFound = true;
                    }
                }
                assertTrue(validationTimeCheckFound);
                assertTrue(validProspectiveChainCheckFound);
                ++trustedCertCounter;
            } else {
                ++untrustedCertCounter;
            }
        }
        assertEquals(2, untrustedCertCounter);
        assertEquals(1, trustedCertCounter);

        boolean signatureTstFound = false;
        for (String timestampId : diagnosticData.getTimestampIdList()) {
            XmlBasicBuildingBlocks timestampBBB = detailedReport.getBasicBuildingBlockById(timestampId);

            xcv = timestampBBB.getXCV();
            assertNotNull(xcv);

            subXCVs = xcv.getSubXCV();
            if (subXCVs.size() == 2) {
                assertEquals(Indication.INDETERMINATE, xcv.getConclusion().getIndication());
                assertEquals(SubIndication.NO_CERTIFICATE_CHAIN_FOUND_NO_POE, xcv.getConclusion().getSubIndication());
                assertTrue(checkMessageValuePresence(convert(xcv.getConclusion().getErrors()), i18nProvider.getMessage(MessageTag.BBB_XCV_HPCCVVT_ANS)));
                signatureTstFound = true;
            }

            untrustedCertCounter = 0;
            trustedCertCounter = 0;
            for (XmlSubXCV subXCV : subXCVs) {
                if (subXCV.isTrustAnchor()) {
                    if (subXCVs.size() == 2) {
                        // sig tst
                        assertEquals(Indication.INDETERMINATE, subXCV.getConclusion().getIndication());
                        assertEquals(SubIndication.NO_CERTIFICATE_CHAIN_FOUND_NO_POE, subXCV.getConclusion().getSubIndication());
                        assertTrue(checkMessageValuePresence(convert(subXCV.getConclusion().getErrors()), i18nProvider.getMessage(MessageTag.BBB_XCV_IOTAA_ANS)));
                        assertTrue(checkMessageValuePresence(convert(subXCV.getConclusion().getWarnings()), i18nProvider.getMessage(MessageTag.BBB_XCV_IVTBCTSD_ANS)));

                        boolean validationTimeCheckFound = false;
                        boolean validProspectiveChainCheckFound = false;
                        for (XmlConstraint xmlConstraint : subXCV.getConstraint()) {
                            if (MessageTag.BBB_XCV_IVTBCTSD.getId().equals(xmlConstraint.getName().getKey())) {
                                assertEquals(XmlStatus.WARNING, xmlConstraint.getStatus());
                                assertEquals(MessageTag.BBB_XCV_IVTBCTSD_ANS.getId(), xmlConstraint.getWarning().getKey());
                                assertEquals(i18nProvider.getMessage(MessageTag.CERTIFICATE_SUNSET_DATE,
                                        ValidationProcessUtils.getFormattedDate(xmlDiagnosticData.getValidationDate()),
                                        ValidationProcessUtils.getFormattedDate(diagnosticData.getCertificateById(subXCV.getId()).getTrustSunsetDate())), xmlConstraint.getAdditionalInfo());
                                validationTimeCheckFound = true;
                            } else if (MessageTag.BBB_XCV_IOTAA.getId().equals(xmlConstraint.getName().getKey())) {
                                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                                assertEquals(MessageTag.BBB_XCV_IOTAA_ANS.getId(), xmlConstraint.getError().getKey());
                                validProspectiveChainCheckFound = true;
                            }
                        }
                        assertTrue(validationTimeCheckFound);
                        assertTrue(validProspectiveChainCheckFound);
                    } else {
                        // arc tst
                        assertEquals(Indication.PASSED, subXCV.getConclusion().getIndication());

                        boolean validationTimeCheckFound = false;
                        boolean validProspectiveChainCheckFound = false;
                        for (XmlConstraint xmlConstraint : subXCV.getConstraint()) {
                            if (MessageTag.BBB_XCV_IVTBCTSD.getId().equals(xmlConstraint.getName().getKey())) {
                                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                                assertEquals(i18nProvider.getMessage(MessageTag.CERTIFICATE_SUNSET_DATE,
                                        ValidationProcessUtils.getFormattedDate(xmlDiagnosticData.getValidationDate()),
                                        ValidationProcessUtils.getFormattedDate(diagnosticData.getCertificateById(subXCV.getId()).getTrustSunsetDate())), xmlConstraint.getAdditionalInfo());
                                validationTimeCheckFound = true;
                            } else if (MessageTag.BBB_XCV_IOTAA.getId().equals(xmlConstraint.getName().getKey())) {
                                validProspectiveChainCheckFound = true;
                            }
                        }
                        assertTrue(validationTimeCheckFound);
                        assertFalse(validProspectiveChainCheckFound);
                    }
                    ++trustedCertCounter;
                } else {
                    ++untrustedCertCounter;
                }
            }
            assertEquals(subXCVs.size() - 1, untrustedCertCounter);
            assertEquals(1, trustedCertCounter);

        }
        assertTrue(signatureTstFound);

        validateBestSigningTimes(reports);
        checkReports(reports);
    }

    @Test
    void expiredSigSunsetDateNoArcTstWarnLevelTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_sunset.xml"));
        assertNotNull(xmlDiagnosticData);

        Calendar calendar = Calendar.getInstance();
        calendar.set(2022, Calendar.FEBRUARY, 1, 0, 0, 0);
        Date validationTime = calendar.getTime();

        xmlDiagnosticData.setValidationDate(validationTime);

        List<XmlFoundTimestamp> foundTimestamps = xmlDiagnosticData.getSignatures().get(0).getFoundTimestamps();
        foundTimestamps.remove(foundTimestamps.get(1));

        List<XmlTimestamp> usedTimestamps = xmlDiagnosticData.getUsedTimestamps();
        usedTimestamps.remove(usedTimestamps.get(1));

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.WARN);
        validationPolicy.getSignatureConstraints().getBasicSignatureConstraints().getCACertificate().setSunsetDate(levelConstraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();
        assertNotNull(reports);

        DiagnosticData diagnosticData = reports.getDiagnosticData();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationWarnings(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_XCV_HPCCVVT_ANS)));

        String firstTstId = simpleReport.getSignatureTimestamps(simpleReport.getFirstSignatureId()).get(0).getId();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(firstTstId));
        assertEquals(SubIndication.NO_CERTIFICATE_CHAIN_FOUND_NO_POE, simpleReport.getSubIndication(firstTstId));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(firstTstId),
                i18nProvider.getMessage(MessageTag.BBB_XCV_HPCCVVT_ANS)));

        DetailedReport detailedReport = reports.getDetailedReport();
        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertNotNull(signatureBBB);
        assertEquals(Indication.PASSED, signatureBBB.getConclusion().getIndication());

        XmlXCV xcv = signatureBBB.getXCV();
        assertNotNull(xcv);
        assertEquals(Indication.PASSED, xcv.getConclusion().getIndication());
        assertTrue(checkMessageValuePresence(convert(xcv.getConclusion().getWarnings()), i18nProvider.getMessage(MessageTag.BBB_XCV_HPCCVVT_ANS)));

        int prospectiveChainFoundCounter = 0;
        int trustAnchorSunsetCheckValidCounter = 0;
        int trustAnchorSunsetCheckInvalidCounter = 0;
        int validProspectiveChainFoundCounter = 0;
        int invalidProspectiveChainFoundCounter = 0;
        int xmlSubXCVCheckValidCounter = 0;
        int xmlSubXCVCheckInvalidCounter = 0;

        for (XmlConstraint xmlConstraint : xcv.getConstraint()) {
            if (MessageTag.BBB_XCV_CCCBB.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                ++prospectiveChainFoundCounter;
            } else if (MessageTag.BBB_XCV_IVTBCTSD.getId().equals(xmlConstraint.getName().getKey())) {
                assertNotNull(xmlConstraint.getId());
                assertEquals(i18nProvider.getMessage(MessageTag.CERTIFICATE_SUNSET_DATE,
                                ValidationProcessUtils.getFormattedDate(xmlDiagnosticData.getValidationDate()),
                                ValidationProcessUtils.getFormattedDate(diagnosticData.getCertificateById(xmlConstraint.getId()).getTrustSunsetDate())),
                        xmlConstraint.getAdditionalInfo());
                if (XmlStatus.OK == xmlConstraint.getStatus()) {
                    ++trustAnchorSunsetCheckValidCounter;
                } else if (XmlStatus.WARNING == xmlConstraint.getStatus()) {
                    assertEquals(MessageTag.BBB_XCV_IVTBCTSD_ANS.getId(), xmlConstraint.getWarning().getKey());
                    ++trustAnchorSunsetCheckInvalidCounter;
                }
            } else if (MessageTag.BBB_XCV_HPCCVVT.getId().equals(xmlConstraint.getName().getKey())) {
                if (XmlStatus.OK == xmlConstraint.getStatus()) {
                    ++validProspectiveChainFoundCounter;
                } else if (XmlStatus.WARNING == xmlConstraint.getStatus()) {
                    assertEquals(MessageTag.BBB_XCV_HPCCVVT_ANS.getId(), xmlConstraint.getWarning().getKey());
                    ++ invalidProspectiveChainFoundCounter;
                }
            } else if (MessageTag.BBB_XCV_SUB.getId().equals(xmlConstraint.getName().getKey())) {
                assertNotNull(xmlConstraint.getId());
                if (XmlStatus.OK == xmlConstraint.getStatus()) {
                    ++xmlSubXCVCheckValidCounter;
                } else if (XmlStatus.NOT_OK == xmlConstraint.getStatus()) {
                    assertEquals(MessageTag.BBB_XCV_SUB_ANS.getId(), xmlConstraint.getError().getKey());
                    ++xmlSubXCVCheckInvalidCounter;
                }
            }
        }

        assertEquals(1, prospectiveChainFoundCounter);
        assertEquals(0, trustAnchorSunsetCheckValidCounter);
        assertEquals(1, trustAnchorSunsetCheckInvalidCounter);
        assertEquals(0, validProspectiveChainFoundCounter);
        assertEquals(1, invalidProspectiveChainFoundCounter);
        assertEquals(3, xmlSubXCVCheckValidCounter);
        assertEquals(0, xmlSubXCVCheckInvalidCounter);

        List<XmlSubXCV> subXCVs = xcv.getSubXCV();
        assertEquals(3, subXCVs.size());

        int untrustedCertCounter = 0;
        int trustedCertCounter = 0;
        for (XmlSubXCV subXCV : subXCVs) {
            if (subXCV.isTrustAnchor()) {
                assertEquals(Indication.PASSED, subXCV.getConclusion().getIndication());
                assertTrue(checkMessageValuePresence(convert(subXCV.getConclusion().getWarnings()), i18nProvider.getMessage(MessageTag.BBB_XCV_IOTAA_ANS)));
                assertTrue(checkMessageValuePresence(convert(subXCV.getConclusion().getWarnings()), i18nProvider.getMessage(MessageTag.BBB_XCV_IVTBCTSD_ANS)));

                boolean validationTimeCheckFound = false;
                boolean validProspectiveChainCheckFound = false;
                for (XmlConstraint xmlConstraint : subXCV.getConstraint()) {
                    if (MessageTag.BBB_XCV_IVTBCTSD.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.WARNING, xmlConstraint.getStatus());
                        assertEquals(MessageTag.BBB_XCV_IVTBCTSD_ANS.getId(), xmlConstraint.getWarning().getKey());
                        assertEquals(i18nProvider.getMessage(MessageTag.CERTIFICATE_SUNSET_DATE,
                                ValidationProcessUtils.getFormattedDate(xmlDiagnosticData.getValidationDate()),
                                ValidationProcessUtils.getFormattedDate(diagnosticData.getCertificateById(subXCV.getId()).getTrustSunsetDate())), xmlConstraint.getAdditionalInfo());
                        validationTimeCheckFound = true;
                    } else if (MessageTag.BBB_XCV_IOTAA.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.WARNING, xmlConstraint.getStatus());
                        assertEquals(MessageTag.BBB_XCV_IOTAA_ANS.getId(), xmlConstraint.getWarning().getKey());
                        validProspectiveChainCheckFound = true;
                    }
                }
                assertTrue(validationTimeCheckFound);
                assertTrue(validProspectiveChainCheckFound);
                ++trustedCertCounter;
            } else {
                ++untrustedCertCounter;
            }
        }
        assertEquals(2, untrustedCertCounter);
        assertEquals(1, trustedCertCounter);

        boolean signatureTstFound = false;
        for (String timestampId : diagnosticData.getTimestampIdList()) {
            XmlBasicBuildingBlocks timestampBBB = detailedReport.getBasicBuildingBlockById(timestampId);

            xcv = timestampBBB.getXCV();
            assertNotNull(xcv);

            subXCVs = xcv.getSubXCV();
            if (subXCVs.size() == 2) {
                assertEquals(Indication.INDETERMINATE, xcv.getConclusion().getIndication());
                assertEquals(SubIndication.NO_CERTIFICATE_CHAIN_FOUND_NO_POE, xcv.getConclusion().getSubIndication());
                assertTrue(checkMessageValuePresence(convert(xcv.getConclusion().getErrors()), i18nProvider.getMessage(MessageTag.BBB_XCV_HPCCVVT_ANS)));
                signatureTstFound = true;
            }

            untrustedCertCounter = 0;
            trustedCertCounter = 0;
            for (XmlSubXCV subXCV : subXCVs) {
                if (subXCV.isTrustAnchor()) {
                    if (subXCVs.size() == 2) {
                        // sig tst
                        assertEquals(Indication.INDETERMINATE, subXCV.getConclusion().getIndication());
                        assertEquals(SubIndication.NO_CERTIFICATE_CHAIN_FOUND_NO_POE, subXCV.getConclusion().getSubIndication());
                        assertTrue(checkMessageValuePresence(convert(subXCV.getConclusion().getErrors()), i18nProvider.getMessage(MessageTag.BBB_XCV_IOTAA_ANS)));
                        assertTrue(checkMessageValuePresence(convert(subXCV.getConclusion().getWarnings()), i18nProvider.getMessage(MessageTag.BBB_XCV_IVTBCTSD_ANS)));

                        boolean validationTimeCheckFound = false;
                        boolean validProspectiveChainCheckFound = false;
                        for (XmlConstraint xmlConstraint : subXCV.getConstraint()) {
                            if (MessageTag.BBB_XCV_IVTBCTSD.getId().equals(xmlConstraint.getName().getKey())) {
                                assertEquals(XmlStatus.WARNING, xmlConstraint.getStatus());
                                assertEquals(MessageTag.BBB_XCV_IVTBCTSD_ANS.getId(), xmlConstraint.getWarning().getKey());
                                assertEquals(i18nProvider.getMessage(MessageTag.CERTIFICATE_SUNSET_DATE,
                                        ValidationProcessUtils.getFormattedDate(xmlDiagnosticData.getValidationDate()),
                                        ValidationProcessUtils.getFormattedDate(diagnosticData.getCertificateById(subXCV.getId()).getTrustSunsetDate())), xmlConstraint.getAdditionalInfo());
                                validationTimeCheckFound = true;
                            } else if (MessageTag.BBB_XCV_IOTAA.getId().equals(xmlConstraint.getName().getKey())) {
                                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                                assertEquals(MessageTag.BBB_XCV_IOTAA_ANS.getId(), xmlConstraint.getError().getKey());
                                validProspectiveChainCheckFound = true;
                            }
                        }
                        assertTrue(validationTimeCheckFound);
                        assertTrue(validProspectiveChainCheckFound);
                    } else {
                        // arc tst
                        assertEquals(Indication.PASSED, subXCV.getConclusion().getIndication());

                        boolean validationTimeCheckFound = false;
                        boolean validProspectiveChainCheckFound = false;
                        for (XmlConstraint xmlConstraint : subXCV.getConstraint()) {
                            if (MessageTag.BBB_XCV_IVTBCTSD.getId().equals(xmlConstraint.getName().getKey())) {
                                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                                assertEquals(i18nProvider.getMessage(MessageTag.CERTIFICATE_SUNSET_DATE,
                                        ValidationProcessUtils.getFormattedDate(xmlDiagnosticData.getValidationDate()),
                                        ValidationProcessUtils.getFormattedDate(diagnosticData.getCertificateById(subXCV.getId()).getTrustSunsetDate())), xmlConstraint.getAdditionalInfo());
                                validationTimeCheckFound = true;
                            } else if (MessageTag.BBB_XCV_IOTAA.getId().equals(xmlConstraint.getName().getKey())) {
                                validProspectiveChainCheckFound = true;
                            }
                        }
                        assertTrue(validationTimeCheckFound);
                        assertFalse(validProspectiveChainCheckFound);
                    }
                    ++trustedCertCounter;
                } else {
                    ++untrustedCertCounter;
                }
            }
            assertEquals(subXCVs.size() - 1, untrustedCertCounter);
            assertEquals(1, trustedCertCounter);

        }
        assertTrue(signatureTstFound);

        validateBestSigningTimes(reports);
        checkReports(reports);
    }

    @Test
    void expiredSigSunsetDateNoArcTstInfoLevelTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_sunset.xml"));
        assertNotNull(xmlDiagnosticData);

        Calendar calendar = Calendar.getInstance();
        calendar.set(2022, Calendar.FEBRUARY, 1, 0, 0, 0);
        Date validationTime = calendar.getTime();

        xmlDiagnosticData.setValidationDate(validationTime);

        List<XmlFoundTimestamp> foundTimestamps = xmlDiagnosticData.getSignatures().get(0).getFoundTimestamps();
        foundTimestamps.remove(foundTimestamps.get(1));

        List<XmlTimestamp> usedTimestamps = xmlDiagnosticData.getUsedTimestamps();
        usedTimestamps.remove(usedTimestamps.get(1));

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.INFORM);
        validationPolicy.getSignatureConstraints().getBasicSignatureConstraints().getCACertificate().setSunsetDate(levelConstraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();
        assertNotNull(reports);

        DiagnosticData diagnosticData = reports.getDiagnosticData();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationInfo(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_XCV_HPCCVVT_ANS)));

        String firstTstId = simpleReport.getSignatureTimestamps(simpleReport.getFirstSignatureId()).get(0).getId();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(firstTstId));
        assertEquals(SubIndication.NO_CERTIFICATE_CHAIN_FOUND_NO_POE, simpleReport.getSubIndication(firstTstId));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(firstTstId),
                i18nProvider.getMessage(MessageTag.BBB_XCV_HPCCVVT_ANS)));

        DetailedReport detailedReport = reports.getDetailedReport();
        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertNotNull(signatureBBB);
        assertEquals(Indication.PASSED, signatureBBB.getConclusion().getIndication());

        XmlXCV xcv = signatureBBB.getXCV();
        assertNotNull(xcv);
        assertEquals(Indication.PASSED, xcv.getConclusion().getIndication());
        assertTrue(checkMessageValuePresence(convert(xcv.getConclusion().getInfos()), i18nProvider.getMessage(MessageTag.BBB_XCV_HPCCVVT_ANS)));

        int prospectiveChainFoundCounter = 0;
        int trustAnchorSunsetCheckValidCounter = 0;
        int trustAnchorSunsetCheckInvalidCounter = 0;
        int validProspectiveChainFoundCounter = 0;
        int invalidProspectiveChainFoundCounter = 0;
        int xmlSubXCVCheckValidCounter = 0;
        int xmlSubXCVCheckInvalidCounter = 0;

        for (XmlConstraint xmlConstraint : xcv.getConstraint()) {
            if (MessageTag.BBB_XCV_CCCBB.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                ++prospectiveChainFoundCounter;
            } else if (MessageTag.BBB_XCV_IVTBCTSD.getId().equals(xmlConstraint.getName().getKey())) {
                assertNotNull(xmlConstraint.getId());
                assertEquals(i18nProvider.getMessage(MessageTag.CERTIFICATE_SUNSET_DATE,
                                ValidationProcessUtils.getFormattedDate(xmlDiagnosticData.getValidationDate()),
                                ValidationProcessUtils.getFormattedDate(diagnosticData.getCertificateById(xmlConstraint.getId()).getTrustSunsetDate())),
                        xmlConstraint.getAdditionalInfo());
                if (XmlStatus.OK == xmlConstraint.getStatus()) {
                    ++trustAnchorSunsetCheckValidCounter;
                } else if (XmlStatus.INFORMATION == xmlConstraint.getStatus()) {
                    assertEquals(MessageTag.BBB_XCV_IVTBCTSD_ANS.getId(), xmlConstraint.getInfo().getKey());
                    ++trustAnchorSunsetCheckInvalidCounter;
                }
            } else if (MessageTag.BBB_XCV_HPCCVVT.getId().equals(xmlConstraint.getName().getKey())) {
                if (XmlStatus.OK == xmlConstraint.getStatus()) {
                    ++validProspectiveChainFoundCounter;
                } else if (XmlStatus.INFORMATION == xmlConstraint.getStatus()) {
                    assertEquals(MessageTag.BBB_XCV_HPCCVVT_ANS.getId(), xmlConstraint.getInfo().getKey());
                    ++ invalidProspectiveChainFoundCounter;
                }
            } else if (MessageTag.BBB_XCV_SUB.getId().equals(xmlConstraint.getName().getKey())) {
                assertNotNull(xmlConstraint.getId());
                if (XmlStatus.OK == xmlConstraint.getStatus()) {
                    ++xmlSubXCVCheckValidCounter;
                } else if (XmlStatus.NOT_OK == xmlConstraint.getStatus()) {
                    assertEquals(MessageTag.BBB_XCV_SUB_ANS.getId(), xmlConstraint.getError().getKey());
                    ++xmlSubXCVCheckInvalidCounter;
                }
            }
        }

        assertEquals(1, prospectiveChainFoundCounter);
        assertEquals(0, trustAnchorSunsetCheckValidCounter);
        assertEquals(1, trustAnchorSunsetCheckInvalidCounter);
        assertEquals(0, validProspectiveChainFoundCounter);
        assertEquals(1, invalidProspectiveChainFoundCounter);
        assertEquals(3, xmlSubXCVCheckValidCounter);
        assertEquals(0, xmlSubXCVCheckInvalidCounter);

        List<XmlSubXCV> subXCVs = xcv.getSubXCV();
        assertEquals(3, subXCVs.size());

        int untrustedCertCounter = 0;
        int trustedCertCounter = 0;
        for (XmlSubXCV subXCV : subXCVs) {
            if (subXCV.isTrustAnchor()) {
                assertEquals(Indication.PASSED, subXCV.getConclusion().getIndication());
                assertTrue(checkMessageValuePresence(convert(subXCV.getConclusion().getInfos()), i18nProvider.getMessage(MessageTag.BBB_XCV_IOTAA_ANS)));
                assertTrue(checkMessageValuePresence(convert(subXCV.getConclusion().getInfos()), i18nProvider.getMessage(MessageTag.BBB_XCV_IVTBCTSD_ANS)));

                boolean validationTimeCheckFound = false;
                boolean validProspectiveChainCheckFound = false;
                for (XmlConstraint xmlConstraint : subXCV.getConstraint()) {
                    if (MessageTag.BBB_XCV_IVTBCTSD.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.INFORMATION, xmlConstraint.getStatus());
                        assertEquals(MessageTag.BBB_XCV_IVTBCTSD_ANS.getId(), xmlConstraint.getInfo().getKey());
                        assertEquals(i18nProvider.getMessage(MessageTag.CERTIFICATE_SUNSET_DATE,
                                ValidationProcessUtils.getFormattedDate(xmlDiagnosticData.getValidationDate()),
                                ValidationProcessUtils.getFormattedDate(diagnosticData.getCertificateById(subXCV.getId()).getTrustSunsetDate())), xmlConstraint.getAdditionalInfo());
                        validationTimeCheckFound = true;
                    } else if (MessageTag.BBB_XCV_IOTAA.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.INFORMATION, xmlConstraint.getStatus());
                        assertEquals(MessageTag.BBB_XCV_IOTAA_ANS.getId(), xmlConstraint.getInfo().getKey());
                        validProspectiveChainCheckFound = true;
                    }
                }
                assertTrue(validationTimeCheckFound);
                assertTrue(validProspectiveChainCheckFound);
                ++trustedCertCounter;
            } else {
                ++untrustedCertCounter;
            }
        }
        assertEquals(2, untrustedCertCounter);
        assertEquals(1, trustedCertCounter);

        boolean signatureTstFound = false;
        for (String timestampId : diagnosticData.getTimestampIdList()) {
            XmlBasicBuildingBlocks timestampBBB = detailedReport.getBasicBuildingBlockById(timestampId);

            xcv = timestampBBB.getXCV();
            assertNotNull(xcv);

            subXCVs = xcv.getSubXCV();
            if (subXCVs.size() == 2) {
                assertEquals(Indication.INDETERMINATE, xcv.getConclusion().getIndication());
                assertEquals(SubIndication.NO_CERTIFICATE_CHAIN_FOUND_NO_POE, xcv.getConclusion().getSubIndication());
                assertTrue(checkMessageValuePresence(convert(xcv.getConclusion().getErrors()), i18nProvider.getMessage(MessageTag.BBB_XCV_HPCCVVT_ANS)));
                signatureTstFound = true;
            }

            untrustedCertCounter = 0;
            trustedCertCounter = 0;
            for (XmlSubXCV subXCV : subXCVs) {
                if (subXCV.isTrustAnchor()) {
                    if (subXCVs.size() == 2) {
                        // sig tst
                        assertEquals(Indication.INDETERMINATE, subXCV.getConclusion().getIndication());
                        assertEquals(SubIndication.NO_CERTIFICATE_CHAIN_FOUND_NO_POE, subXCV.getConclusion().getSubIndication());
                        assertTrue(checkMessageValuePresence(convert(subXCV.getConclusion().getErrors()), i18nProvider.getMessage(MessageTag.BBB_XCV_IOTAA_ANS)));
                        assertTrue(checkMessageValuePresence(convert(subXCV.getConclusion().getWarnings()), i18nProvider.getMessage(MessageTag.BBB_XCV_IVTBCTSD_ANS)));

                        boolean validationTimeCheckFound = false;
                        boolean validProspectiveChainCheckFound = false;
                        for (XmlConstraint xmlConstraint : subXCV.getConstraint()) {
                            if (MessageTag.BBB_XCV_IVTBCTSD.getId().equals(xmlConstraint.getName().getKey())) {
                                assertEquals(XmlStatus.WARNING, xmlConstraint.getStatus());
                                assertEquals(MessageTag.BBB_XCV_IVTBCTSD_ANS.getId(), xmlConstraint.getWarning().getKey());
                                assertEquals(i18nProvider.getMessage(MessageTag.CERTIFICATE_SUNSET_DATE,
                                        ValidationProcessUtils.getFormattedDate(xmlDiagnosticData.getValidationDate()),
                                        ValidationProcessUtils.getFormattedDate(diagnosticData.getCertificateById(subXCV.getId()).getTrustSunsetDate())), xmlConstraint.getAdditionalInfo());
                                validationTimeCheckFound = true;
                            } else if (MessageTag.BBB_XCV_IOTAA.getId().equals(xmlConstraint.getName().getKey())) {
                                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                                assertEquals(MessageTag.BBB_XCV_IOTAA_ANS.getId(), xmlConstraint.getError().getKey());
                                validProspectiveChainCheckFound = true;
                            }
                        }
                        assertTrue(validationTimeCheckFound);
                        assertTrue(validProspectiveChainCheckFound);
                    } else {
                        // arc tst
                        assertEquals(Indication.PASSED, subXCV.getConclusion().getIndication());

                        boolean validationTimeCheckFound = false;
                        boolean validProspectiveChainCheckFound = false;
                        for (XmlConstraint xmlConstraint : subXCV.getConstraint()) {
                            if (MessageTag.BBB_XCV_IVTBCTSD.getId().equals(xmlConstraint.getName().getKey())) {
                                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                                assertEquals(i18nProvider.getMessage(MessageTag.CERTIFICATE_SUNSET_DATE,
                                        ValidationProcessUtils.getFormattedDate(xmlDiagnosticData.getValidationDate()),
                                        ValidationProcessUtils.getFormattedDate(diagnosticData.getCertificateById(subXCV.getId()).getTrustSunsetDate())), xmlConstraint.getAdditionalInfo());
                                validationTimeCheckFound = true;
                            } else if (MessageTag.BBB_XCV_IOTAA.getId().equals(xmlConstraint.getName().getKey())) {
                                validProspectiveChainCheckFound = true;
                            }
                        }
                        assertTrue(validationTimeCheckFound);
                        assertFalse(validProspectiveChainCheckFound);
                    }
                    ++trustedCertCounter;
                } else {
                    ++untrustedCertCounter;
                }
            }
            assertEquals(subXCVs.size() - 1, untrustedCertCounter);
            assertEquals(1, trustedCertCounter);

        }
        assertTrue(signatureTstFound);

        validateBestSigningTimes(reports);
        checkReports(reports);
    }

    @Test
    void expiredSigSunsetDateNoArcTstIgnoreLevelTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_sunset.xml"));
        assertNotNull(xmlDiagnosticData);

        Calendar calendar = Calendar.getInstance();
        calendar.set(2022, Calendar.FEBRUARY, 1, 0, 0, 0);
        Date validationTime = calendar.getTime();

        xmlDiagnosticData.setValidationDate(validationTime);

        List<XmlFoundTimestamp> foundTimestamps = xmlDiagnosticData.getSignatures().get(0).getFoundTimestamps();
        foundTimestamps.remove(foundTimestamps.get(1));

        List<XmlTimestamp> usedTimestamps = xmlDiagnosticData.getUsedTimestamps();
        usedTimestamps.remove(usedTimestamps.get(1));

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.IGNORE);
        validationPolicy.getSignatureConstraints().getBasicSignatureConstraints().getCACertificate().setSunsetDate(levelConstraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();
        assertNotNull(reports);

        DiagnosticData diagnosticData = reports.getDiagnosticData();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertFalse(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_XCV_HPCCVVT_ANS)));
        assertFalse(checkMessageValuePresence(simpleReport.getAdESValidationWarnings(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_XCV_HPCCVVT_ANS)));
        assertFalse(checkMessageValuePresence(simpleReport.getAdESValidationInfo(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_XCV_HPCCVVT_ANS)));

        String firstTstId = simpleReport.getSignatureTimestamps(simpleReport.getFirstSignatureId()).get(0).getId();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(firstTstId));
        assertEquals(SubIndication.NO_CERTIFICATE_CHAIN_FOUND_NO_POE, simpleReport.getSubIndication(firstTstId));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(firstTstId),
                i18nProvider.getMessage(MessageTag.BBB_XCV_HPCCVVT_ANS)));

        DetailedReport detailedReport = reports.getDetailedReport();
        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertNotNull(signatureBBB);
        assertEquals(Indication.PASSED, signatureBBB.getConclusion().getIndication());

        XmlXCV xcv = signatureBBB.getXCV();
        assertNotNull(xcv);
        assertEquals(Indication.PASSED, xcv.getConclusion().getIndication());
        assertFalse(checkMessageValuePresence(convert(xcv.getConclusion().getErrors()), i18nProvider.getMessage(MessageTag.BBB_XCV_HPCCVVT_ANS)));
        assertFalse(checkMessageValuePresence(convert(xcv.getConclusion().getWarnings()), i18nProvider.getMessage(MessageTag.BBB_XCV_HPCCVVT_ANS)));
        assertFalse(checkMessageValuePresence(convert(xcv.getConclusion().getInfos()), i18nProvider.getMessage(MessageTag.BBB_XCV_HPCCVVT_ANS)));

        int prospectiveChainFoundCounter = 0;
        int trustAnchorSunsetCheckValidCounter = 0;
        int trustAnchorSunsetCheckInvalidCounter = 0;
        int validProspectiveChainFoundCounter = 0;
        int invalidProspectiveChainFoundCounter = 0;
        int xmlSubXCVCheckValidCounter = 0;
        int xmlSubXCVCheckInvalidCounter = 0;

        for (XmlConstraint xmlConstraint : xcv.getConstraint()) {
            if (MessageTag.BBB_XCV_CCCBB.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                ++prospectiveChainFoundCounter;
            } else if (MessageTag.BBB_XCV_IVTBCTSD.getId().equals(xmlConstraint.getName().getKey())) {
                assertNotNull(xmlConstraint.getId());
                assertNull(xmlConstraint.getAdditionalInfo());
                if (XmlStatus.OK == xmlConstraint.getStatus()) {
                    ++trustAnchorSunsetCheckValidCounter;
                } else if (XmlStatus.IGNORED == xmlConstraint.getStatus()) {
                    ++trustAnchorSunsetCheckInvalidCounter;
                }
            } else if (MessageTag.BBB_XCV_HPCCVVT.getId().equals(xmlConstraint.getName().getKey())) {
                if (XmlStatus.OK == xmlConstraint.getStatus()) {
                    ++validProspectiveChainFoundCounter;
                } else if (XmlStatus.IGNORED == xmlConstraint.getStatus()) {
                    ++invalidProspectiveChainFoundCounter;
                }
            } else if (MessageTag.BBB_XCV_SUB.getId().equals(xmlConstraint.getName().getKey())) {
                assertNotNull(xmlConstraint.getId());
                if (XmlStatus.OK == xmlConstraint.getStatus()) {
                    ++xmlSubXCVCheckValidCounter;
                } else if (XmlStatus.NOT_OK == xmlConstraint.getStatus()) {
                    assertEquals(MessageTag.BBB_XCV_SUB_ANS.getId(), xmlConstraint.getError().getKey());
                    ++xmlSubXCVCheckInvalidCounter;
                }
            }
        }

        assertEquals(1, prospectiveChainFoundCounter);
        assertEquals(0, trustAnchorSunsetCheckValidCounter);
        assertEquals(1, trustAnchorSunsetCheckInvalidCounter);
        assertEquals(0, validProspectiveChainFoundCounter);
        assertEquals(1, invalidProspectiveChainFoundCounter);
        assertEquals(3, xmlSubXCVCheckValidCounter);
        assertEquals(0, xmlSubXCVCheckInvalidCounter);

        List<XmlSubXCV> subXCVs = xcv.getSubXCV();
        assertEquals(3, subXCVs.size());

        int untrustedCertCounter = 0;
        int trustedCertCounter = 0;
        for (XmlSubXCV subXCV : subXCVs) {
            if (subXCV.isTrustAnchor()) {
                assertEquals(Indication.PASSED, subXCV.getConclusion().getIndication());
                assertFalse(checkMessageValuePresence(convert(subXCV.getConclusion().getErrors()), i18nProvider.getMessage(MessageTag.BBB_XCV_IOTAA_ANS)));
                assertFalse(checkMessageValuePresence(convert(subXCV.getConclusion().getErrors()), i18nProvider.getMessage(MessageTag.BBB_XCV_IVTBCTSD_ANS)));
                assertFalse(checkMessageValuePresence(convert(subXCV.getConclusion().getWarnings()), i18nProvider.getMessage(MessageTag.BBB_XCV_IOTAA_ANS)));
                assertFalse(checkMessageValuePresence(convert(subXCV.getConclusion().getWarnings()), i18nProvider.getMessage(MessageTag.BBB_XCV_IVTBCTSD_ANS)));
                assertFalse(checkMessageValuePresence(convert(subXCV.getConclusion().getInfos()), i18nProvider.getMessage(MessageTag.BBB_XCV_IOTAA_ANS)));
                assertFalse(checkMessageValuePresence(convert(subXCV.getConclusion().getInfos()), i18nProvider.getMessage(MessageTag.BBB_XCV_IVTBCTSD_ANS)));

                boolean validationTimeCheckFound = false;
                boolean validProspectiveChainCheckFound = false;
                for (XmlConstraint xmlConstraint : subXCV.getConstraint()) {
                    if (MessageTag.BBB_XCV_IVTBCTSD.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.IGNORED, xmlConstraint.getStatus());
                        assertNull(xmlConstraint.getAdditionalInfo());
                        validationTimeCheckFound = true;
                    } else if (MessageTag.BBB_XCV_IOTAA.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.IGNORED, xmlConstraint.getStatus());
                        validProspectiveChainCheckFound = true;
                    }
                }
                assertTrue(validationTimeCheckFound);
                assertTrue(validProspectiveChainCheckFound);
                ++trustedCertCounter;
            } else {
                ++untrustedCertCounter;
            }
        }
        assertEquals(2, untrustedCertCounter);
        assertEquals(1, trustedCertCounter);

        boolean signatureTstFound = false;
        for (String timestampId : diagnosticData.getTimestampIdList()) {
            XmlBasicBuildingBlocks timestampBBB = detailedReport.getBasicBuildingBlockById(timestampId);

            xcv = timestampBBB.getXCV();
            assertNotNull(xcv);

            subXCVs = xcv.getSubXCV();
            if (subXCVs.size() == 2) {
                assertEquals(Indication.INDETERMINATE, xcv.getConclusion().getIndication());
                assertEquals(SubIndication.NO_CERTIFICATE_CHAIN_FOUND_NO_POE, xcv.getConclusion().getSubIndication());
                assertTrue(checkMessageValuePresence(convert(xcv.getConclusion().getErrors()), i18nProvider.getMessage(MessageTag.BBB_XCV_HPCCVVT_ANS)));
                signatureTstFound = true;
            }

            untrustedCertCounter = 0;
            trustedCertCounter = 0;
            for (XmlSubXCV subXCV : subXCVs) {
                if (subXCV.isTrustAnchor()) {
                    if (subXCVs.size() == 2) {
                        // sig tst
                        assertEquals(Indication.INDETERMINATE, subXCV.getConclusion().getIndication());
                        assertEquals(SubIndication.NO_CERTIFICATE_CHAIN_FOUND_NO_POE, subXCV.getConclusion().getSubIndication());
                        assertTrue(checkMessageValuePresence(convert(subXCV.getConclusion().getErrors()), i18nProvider.getMessage(MessageTag.BBB_XCV_IOTAA_ANS)));
                        assertTrue(checkMessageValuePresence(convert(subXCV.getConclusion().getWarnings()), i18nProvider.getMessage(MessageTag.BBB_XCV_IVTBCTSD_ANS)));

                        boolean validationTimeCheckFound = false;
                        boolean validProspectiveChainCheckFound = false;
                        for (XmlConstraint xmlConstraint : subXCV.getConstraint()) {
                            if (MessageTag.BBB_XCV_IVTBCTSD.getId().equals(xmlConstraint.getName().getKey())) {
                                assertEquals(XmlStatus.WARNING, xmlConstraint.getStatus());
                                assertEquals(MessageTag.BBB_XCV_IVTBCTSD_ANS.getId(), xmlConstraint.getWarning().getKey());
                                assertEquals(i18nProvider.getMessage(MessageTag.CERTIFICATE_SUNSET_DATE,
                                        ValidationProcessUtils.getFormattedDate(xmlDiagnosticData.getValidationDate()),
                                        ValidationProcessUtils.getFormattedDate(diagnosticData.getCertificateById(subXCV.getId()).getTrustSunsetDate())), xmlConstraint.getAdditionalInfo());
                                validationTimeCheckFound = true;
                            } else if (MessageTag.BBB_XCV_IOTAA.getId().equals(xmlConstraint.getName().getKey())) {
                                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                                assertEquals(MessageTag.BBB_XCV_IOTAA_ANS.getId(), xmlConstraint.getError().getKey());
                                validProspectiveChainCheckFound = true;
                            }
                        }
                        assertTrue(validationTimeCheckFound);
                        assertTrue(validProspectiveChainCheckFound);
                    } else {
                        // arc tst
                        assertEquals(Indication.PASSED, subXCV.getConclusion().getIndication());

                        boolean validationTimeCheckFound = false;
                        boolean validProspectiveChainCheckFound = false;
                        for (XmlConstraint xmlConstraint : subXCV.getConstraint()) {
                            if (MessageTag.BBB_XCV_IVTBCTSD.getId().equals(xmlConstraint.getName().getKey())) {
                                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                                assertEquals(i18nProvider.getMessage(MessageTag.CERTIFICATE_SUNSET_DATE,
                                        ValidationProcessUtils.getFormattedDate(xmlDiagnosticData.getValidationDate()),
                                        ValidationProcessUtils.getFormattedDate(diagnosticData.getCertificateById(subXCV.getId()).getTrustSunsetDate())), xmlConstraint.getAdditionalInfo());
                                validationTimeCheckFound = true;
                            } else if (MessageTag.BBB_XCV_IOTAA.getId().equals(xmlConstraint.getName().getKey())) {
                                validProspectiveChainCheckFound = true;
                            }
                        }
                        assertTrue(validationTimeCheckFound);
                        assertFalse(validProspectiveChainCheckFound);
                    }
                    ++trustedCertCounter;
                } else {
                    ++untrustedCertCounter;
                }
            }
            assertEquals(subXCVs.size() - 1, untrustedCertCounter);
            assertEquals(1, trustedCertCounter);

        }
        assertTrue(signatureTstFound);

        validateBestSigningTimes(reports);
        checkReports(reports);
    }

    @Test
    void expiredSigSunsetDateNoArcTstNullLevelTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_sunset.xml"));
        assertNotNull(xmlDiagnosticData);

        Calendar calendar = Calendar.getInstance();
        calendar.set(2022, Calendar.FEBRUARY, 1, 0, 0, 0);
        Date validationTime = calendar.getTime();

        xmlDiagnosticData.setValidationDate(validationTime);

        List<XmlFoundTimestamp> foundTimestamps = xmlDiagnosticData.getSignatures().get(0).getFoundTimestamps();
        foundTimestamps.remove(foundTimestamps.get(1));

        List<XmlTimestamp> usedTimestamps = xmlDiagnosticData.getUsedTimestamps();
        usedTimestamps.remove(usedTimestamps.get(1));

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        validationPolicy.getSignatureConstraints().getBasicSignatureConstraints().getCACertificate().setSunsetDate(null);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();
        assertNotNull(reports);

        DiagnosticData diagnosticData = reports.getDiagnosticData();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertFalse(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_XCV_HPCCVVT_ANS)));
        assertFalse(checkMessageValuePresence(simpleReport.getAdESValidationWarnings(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_XCV_HPCCVVT_ANS)));
        assertFalse(checkMessageValuePresence(simpleReport.getAdESValidationInfo(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_XCV_HPCCVVT_ANS)));

        String firstTstId = simpleReport.getSignatureTimestamps(simpleReport.getFirstSignatureId()).get(0).getId();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(firstTstId));
        assertEquals(SubIndication.NO_CERTIFICATE_CHAIN_FOUND_NO_POE, simpleReport.getSubIndication(firstTstId));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(firstTstId),
                i18nProvider.getMessage(MessageTag.BBB_XCV_HPCCVVT_ANS)));

        DetailedReport detailedReport = reports.getDetailedReport();
        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertNotNull(signatureBBB);
        assertEquals(Indication.PASSED, signatureBBB.getConclusion().getIndication());

        XmlXCV xcv = signatureBBB.getXCV();
        assertNotNull(xcv);
        assertEquals(Indication.PASSED, xcv.getConclusion().getIndication());
        assertFalse(checkMessageValuePresence(convert(xcv.getConclusion().getErrors()), i18nProvider.getMessage(MessageTag.BBB_XCV_HPCCVVT_ANS)));
        assertFalse(checkMessageValuePresence(convert(xcv.getConclusion().getWarnings()), i18nProvider.getMessage(MessageTag.BBB_XCV_HPCCVVT_ANS)));
        assertFalse(checkMessageValuePresence(convert(xcv.getConclusion().getInfos()), i18nProvider.getMessage(MessageTag.BBB_XCV_HPCCVVT_ANS)));

        int prospectiveChainFoundCounter = 0;
        int trustAnchorSunsetCheckValidCounter = 0;
        int trustAnchorSunsetCheckInvalidCounter = 0;
        int validProspectiveChainFoundCounter = 0;
        int invalidProspectiveChainFoundCounter = 0;
        int xmlSubXCVCheckValidCounter = 0;
        int xmlSubXCVCheckInvalidCounter = 0;

        for (XmlConstraint xmlConstraint : xcv.getConstraint()) {
            if (MessageTag.BBB_XCV_CCCBB.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                ++prospectiveChainFoundCounter;
            } else if (MessageTag.BBB_XCV_IVTBCTSD.getId().equals(xmlConstraint.getName().getKey())) {
                assertNotNull(xmlConstraint.getId());
                assertNull(xmlConstraint.getAdditionalInfo());
                if (XmlStatus.OK == xmlConstraint.getStatus()) {
                    ++trustAnchorSunsetCheckValidCounter;
                } else {
                    ++trustAnchorSunsetCheckInvalidCounter;
                }
            } else if (MessageTag.BBB_XCV_HPCCVVT.getId().equals(xmlConstraint.getName().getKey())) {
                if (XmlStatus.OK == xmlConstraint.getStatus()) {
                    ++validProspectiveChainFoundCounter;
                } else {
                    ++invalidProspectiveChainFoundCounter;
                }
            } else if (MessageTag.BBB_XCV_SUB.getId().equals(xmlConstraint.getName().getKey())) {
                assertNotNull(xmlConstraint.getId());
                if (XmlStatus.OK == xmlConstraint.getStatus()) {
                    ++xmlSubXCVCheckValidCounter;
                } else if (XmlStatus.NOT_OK == xmlConstraint.getStatus()) {
                    assertEquals(MessageTag.BBB_XCV_SUB_ANS.getId(), xmlConstraint.getError().getKey());
                    ++xmlSubXCVCheckInvalidCounter;
                }
            }
        }

        assertEquals(1, prospectiveChainFoundCounter);
        assertEquals(0, trustAnchorSunsetCheckValidCounter);
        assertEquals(0, trustAnchorSunsetCheckInvalidCounter);
        assertEquals(0, validProspectiveChainFoundCounter);
        assertEquals(0, invalidProspectiveChainFoundCounter);
        assertEquals(3, xmlSubXCVCheckValidCounter);
        assertEquals(0, xmlSubXCVCheckInvalidCounter);

        List<XmlSubXCV> subXCVs = xcv.getSubXCV();
        assertEquals(3, subXCVs.size());

        int untrustedCertCounter = 0;
        int trustedCertCounter = 0;
        for (XmlSubXCV subXCV : subXCVs) {
            if (subXCV.isTrustAnchor()) {
                assertEquals(Indication.PASSED, subXCV.getConclusion().getIndication());
                assertFalse(checkMessageValuePresence(convert(subXCV.getConclusion().getErrors()), i18nProvider.getMessage(MessageTag.BBB_XCV_IOTAA_ANS)));
                assertFalse(checkMessageValuePresence(convert(subXCV.getConclusion().getErrors()), i18nProvider.getMessage(MessageTag.BBB_XCV_IVTBCTSD_ANS)));
                assertFalse(checkMessageValuePresence(convert(subXCV.getConclusion().getWarnings()), i18nProvider.getMessage(MessageTag.BBB_XCV_IOTAA_ANS)));
                assertFalse(checkMessageValuePresence(convert(subXCV.getConclusion().getWarnings()), i18nProvider.getMessage(MessageTag.BBB_XCV_IVTBCTSD_ANS)));
                assertFalse(checkMessageValuePresence(convert(subXCV.getConclusion().getInfos()), i18nProvider.getMessage(MessageTag.BBB_XCV_IOTAA_ANS)));
                assertFalse(checkMessageValuePresence(convert(subXCV.getConclusion().getInfos()), i18nProvider.getMessage(MessageTag.BBB_XCV_IVTBCTSD_ANS)));

                boolean validationTimeCheckFound = false;
                boolean validProspectiveChainCheckFound = false;
                for (XmlConstraint xmlConstraint : subXCV.getConstraint()) {
                    if (MessageTag.BBB_XCV_IVTBCTSD.getId().equals(xmlConstraint.getName().getKey())) {
                        assertNull(xmlConstraint.getAdditionalInfo());
                        validationTimeCheckFound = true;
                    } else if (MessageTag.BBB_XCV_IOTAA.getId().equals(xmlConstraint.getName().getKey())) {
                        validProspectiveChainCheckFound = true;
                    }
                }
                assertFalse(validationTimeCheckFound);
                assertFalse(validProspectiveChainCheckFound);
                ++trustedCertCounter;
            } else {
                ++untrustedCertCounter;
            }
        }
        assertEquals(2, untrustedCertCounter);
        assertEquals(1, trustedCertCounter);

        boolean signatureTstFound = false;
        for (String timestampId : diagnosticData.getTimestampIdList()) {
            XmlBasicBuildingBlocks timestampBBB = detailedReport.getBasicBuildingBlockById(timestampId);

            xcv = timestampBBB.getXCV();
            assertNotNull(xcv);

            subXCVs = xcv.getSubXCV();
            if (subXCVs.size() == 2) {
                assertEquals(Indication.INDETERMINATE, xcv.getConclusion().getIndication());
                assertEquals(SubIndication.NO_CERTIFICATE_CHAIN_FOUND_NO_POE, xcv.getConclusion().getSubIndication());
                assertTrue(checkMessageValuePresence(convert(xcv.getConclusion().getErrors()), i18nProvider.getMessage(MessageTag.BBB_XCV_HPCCVVT_ANS)));
                signatureTstFound = true;
            }

            untrustedCertCounter = 0;
            trustedCertCounter = 0;
            for (XmlSubXCV subXCV : subXCVs) {
                if (subXCV.isTrustAnchor()) {
                    if (subXCVs.size() == 2) {
                        // sig tst
                        assertEquals(Indication.INDETERMINATE, subXCV.getConclusion().getIndication());
                        assertEquals(SubIndication.NO_CERTIFICATE_CHAIN_FOUND_NO_POE, subXCV.getConclusion().getSubIndication());
                        assertTrue(checkMessageValuePresence(convert(subXCV.getConclusion().getErrors()), i18nProvider.getMessage(MessageTag.BBB_XCV_IOTAA_ANS)));
                        assertTrue(checkMessageValuePresence(convert(subXCV.getConclusion().getWarnings()), i18nProvider.getMessage(MessageTag.BBB_XCV_IVTBCTSD_ANS)));

                        boolean validationTimeCheckFound = false;
                        boolean validProspectiveChainCheckFound = false;
                        for (XmlConstraint xmlConstraint : subXCV.getConstraint()) {
                            if (MessageTag.BBB_XCV_IVTBCTSD.getId().equals(xmlConstraint.getName().getKey())) {
                                assertEquals(XmlStatus.WARNING, xmlConstraint.getStatus());
                                assertEquals(MessageTag.BBB_XCV_IVTBCTSD_ANS.getId(), xmlConstraint.getWarning().getKey());
                                assertEquals(i18nProvider.getMessage(MessageTag.CERTIFICATE_SUNSET_DATE,
                                        ValidationProcessUtils.getFormattedDate(xmlDiagnosticData.getValidationDate()),
                                        ValidationProcessUtils.getFormattedDate(diagnosticData.getCertificateById(subXCV.getId()).getTrustSunsetDate())), xmlConstraint.getAdditionalInfo());
                                validationTimeCheckFound = true;
                            } else if (MessageTag.BBB_XCV_IOTAA.getId().equals(xmlConstraint.getName().getKey())) {
                                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                                assertEquals(MessageTag.BBB_XCV_IOTAA_ANS.getId(), xmlConstraint.getError().getKey());
                                validProspectiveChainCheckFound = true;
                            }
                        }
                        assertTrue(validationTimeCheckFound);
                        assertTrue(validProspectiveChainCheckFound);
                    } else {
                        // arc tst
                        assertEquals(Indication.PASSED, subXCV.getConclusion().getIndication());

                        boolean validationTimeCheckFound = false;
                        boolean validProspectiveChainCheckFound = false;
                        for (XmlConstraint xmlConstraint : subXCV.getConstraint()) {
                            if (MessageTag.BBB_XCV_IVTBCTSD.getId().equals(xmlConstraint.getName().getKey())) {
                                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                                assertEquals(i18nProvider.getMessage(MessageTag.CERTIFICATE_SUNSET_DATE,
                                        ValidationProcessUtils.getFormattedDate(xmlDiagnosticData.getValidationDate()),
                                        ValidationProcessUtils.getFormattedDate(diagnosticData.getCertificateById(subXCV.getId()).getTrustSunsetDate())), xmlConstraint.getAdditionalInfo());
                                validationTimeCheckFound = true;
                            } else if (MessageTag.BBB_XCV_IOTAA.getId().equals(xmlConstraint.getName().getKey())) {
                                validProspectiveChainCheckFound = true;
                            }
                        }
                        assertTrue(validationTimeCheckFound);
                        assertFalse(validProspectiveChainCheckFound);
                    }
                    ++trustedCertCounter;
                } else {
                    ++untrustedCertCounter;
                }
            }
            assertEquals(subXCVs.size() - 1, untrustedCertCounter);
            assertEquals(1, trustedCertCounter);

        }
        assertTrue(signatureTstFound);

        validateBestSigningTimes(reports);
        checkReports(reports);
    }

    // TODO : sigTst is not enough to recover from NO_CERTIFICATE_CHAIN_NO_POE (limitation in the standard)
    @Test
    void expiredSigSunsetDateNoArcTstWarnTstLevelTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_sunset.xml"));
        assertNotNull(xmlDiagnosticData);

        Calendar calendar = Calendar.getInstance();
        calendar.set(2022, Calendar.FEBRUARY, 1, 0, 0, 0);
        Date validationTime = calendar.getTime();

        xmlDiagnosticData.setValidationDate(validationTime);

        List<XmlFoundTimestamp> foundTimestamps = xmlDiagnosticData.getSignatures().get(0).getFoundTimestamps();
        foundTimestamps.remove(foundTimestamps.get(1));

        List<XmlTimestamp> usedTimestamps = xmlDiagnosticData.getUsedTimestamps();
        usedTimestamps.remove(usedTimestamps.get(1));

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.WARN);
        validationPolicy.getTimestampConstraints().getBasicSignatureConstraints().getCACertificate().setSunsetDate(constraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();
        assertNotNull(reports);

        DiagnosticData diagnosticData = reports.getDiagnosticData();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.NO_CERTIFICATE_CHAIN_FOUND_NO_POE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_XCV_HPCCVVT_ANS)));

        String firstTstId = simpleReport.getSignatureTimestamps(simpleReport.getFirstSignatureId()).get(0).getId();
        assertEquals(Indication.PASSED, simpleReport.getIndication(firstTstId));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationWarnings(firstTstId),
                i18nProvider.getMessage(MessageTag.BBB_XCV_HPCCVVT_ANS)));

        DetailedReport detailedReport = reports.getDetailedReport();
        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertNotNull(signatureBBB);
        assertEquals(Indication.INDETERMINATE, signatureBBB.getConclusion().getIndication());
        assertEquals(SubIndication.NO_CERTIFICATE_CHAIN_FOUND_NO_POE, signatureBBB.getConclusion().getSubIndication());

        XmlXCV xcv = signatureBBB.getXCV();
        assertNotNull(xcv);
        assertEquals(Indication.INDETERMINATE, xcv.getConclusion().getIndication());
        assertEquals(SubIndication.NO_CERTIFICATE_CHAIN_FOUND_NO_POE, xcv.getConclusion().getSubIndication());
        assertTrue(checkMessageValuePresence(convert(xcv.getConclusion().getErrors()), i18nProvider.getMessage(MessageTag.BBB_XCV_HPCCVVT_ANS)));

        int prospectiveChainFoundCounter = 0;
        int trustAnchorSunsetCheckValidCounter = 0;
        int trustAnchorSunsetCheckInvalidCounter = 0;
        int validProspectiveChainFoundCounter = 0;
        int invalidProspectiveChainFoundCounter = 0;
        int xmlSubXCVCheckValidCounter = 0;
        int xmlSubXCVCheckInvalidCounter = 0;

        for (XmlConstraint xmlConstraint : xcv.getConstraint()) {
            if (MessageTag.BBB_XCV_CCCBB.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                ++prospectiveChainFoundCounter;
            } else if (MessageTag.BBB_XCV_IVTBCTSD.getId().equals(xmlConstraint.getName().getKey())) {
                assertNotNull(xmlConstraint.getId());
                assertEquals(i18nProvider.getMessage(MessageTag.CERTIFICATE_SUNSET_DATE,
                                ValidationProcessUtils.getFormattedDate(xmlDiagnosticData.getValidationDate()),
                                ValidationProcessUtils.getFormattedDate(diagnosticData.getCertificateById(xmlConstraint.getId()).getTrustSunsetDate())),
                        xmlConstraint.getAdditionalInfo());
                if (XmlStatus.OK == xmlConstraint.getStatus()) {
                    ++trustAnchorSunsetCheckValidCounter;
                } else if (XmlStatus.WARNING == xmlConstraint.getStatus()) {
                    assertEquals(MessageTag.BBB_XCV_IVTBCTSD_ANS.getId(), xmlConstraint.getWarning().getKey());
                    ++trustAnchorSunsetCheckInvalidCounter;
                }
            } else if (MessageTag.BBB_XCV_HPCCVVT.getId().equals(xmlConstraint.getName().getKey())) {
                if (XmlStatus.OK == xmlConstraint.getStatus()) {
                    ++validProspectiveChainFoundCounter;
                } else if (XmlStatus.NOT_OK == xmlConstraint.getStatus()) {
                    assertEquals(MessageTag.BBB_XCV_HPCCVVT_ANS.getId(), xmlConstraint.getError().getKey());
                    ++ invalidProspectiveChainFoundCounter;
                }
            } else if (MessageTag.BBB_XCV_SUB.getId().equals(xmlConstraint.getName().getKey())) {
                assertNotNull(xmlConstraint.getId());
                if (XmlStatus.OK == xmlConstraint.getStatus()) {
                    ++xmlSubXCVCheckValidCounter;
                } else if (XmlStatus.NOT_OK == xmlConstraint.getStatus()) {
                    assertEquals(MessageTag.BBB_XCV_SUB_ANS.getId(), xmlConstraint.getError().getKey());
                    ++xmlSubXCVCheckInvalidCounter;
                }
            }
        }

        assertEquals(1, prospectiveChainFoundCounter);
        assertEquals(0, trustAnchorSunsetCheckValidCounter);
        assertEquals(1, trustAnchorSunsetCheckInvalidCounter);
        assertEquals(0, validProspectiveChainFoundCounter);
        assertEquals(1, invalidProspectiveChainFoundCounter);
        assertEquals(0, xmlSubXCVCheckValidCounter);
        assertEquals(0, xmlSubXCVCheckInvalidCounter);

        List<XmlSubXCV> subXCVs = xcv.getSubXCV();
        assertEquals(3, subXCVs.size());

        int untrustedCertCounter = 0;
        int trustedCertCounter = 0;
        for (XmlSubXCV subXCV : subXCVs) {
            if (subXCV.isTrustAnchor()) {
                assertEquals(Indication.INDETERMINATE, subXCV.getConclusion().getIndication());
                assertEquals(SubIndication.NO_CERTIFICATE_CHAIN_FOUND_NO_POE, subXCV.getConclusion().getSubIndication());
                assertTrue(checkMessageValuePresence(convert(subXCV.getConclusion().getErrors()), i18nProvider.getMessage(MessageTag.BBB_XCV_IOTAA_ANS)));
                assertTrue(checkMessageValuePresence(convert(subXCV.getConclusion().getWarnings()), i18nProvider.getMessage(MessageTag.BBB_XCV_IVTBCTSD_ANS)));

                boolean validationTimeCheckFound = false;
                boolean validProspectiveChainCheckFound = false;
                for (XmlConstraint xmlConstraint : subXCV.getConstraint()) {
                    if (MessageTag.BBB_XCV_IVTBCTSD.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.WARNING, xmlConstraint.getStatus());
                        assertEquals(MessageTag.BBB_XCV_IVTBCTSD_ANS.getId(), xmlConstraint.getWarning().getKey());
                        assertEquals(i18nProvider.getMessage(MessageTag.CERTIFICATE_SUNSET_DATE,
                                ValidationProcessUtils.getFormattedDate(xmlDiagnosticData.getValidationDate()),
                                ValidationProcessUtils.getFormattedDate(diagnosticData.getCertificateById(subXCV.getId()).getTrustSunsetDate())), xmlConstraint.getAdditionalInfo());
                        validationTimeCheckFound = true;
                    } else if (MessageTag.BBB_XCV_IOTAA.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                        assertEquals(MessageTag.BBB_XCV_IOTAA_ANS.getId(), xmlConstraint.getError().getKey());
                        validProspectiveChainCheckFound = true;
                    }
                }
                assertTrue(validationTimeCheckFound);
                assertTrue(validProspectiveChainCheckFound);
                ++trustedCertCounter;
            } else {
                ++untrustedCertCounter;
            }
        }
        assertEquals(2, untrustedCertCounter);
        assertEquals(1, trustedCertCounter);

        boolean signatureTstFound = false;
        for (String timestampId : diagnosticData.getTimestampIdList()) {
            XmlBasicBuildingBlocks timestampBBB = detailedReport.getBasicBuildingBlockById(timestampId);

            xcv = timestampBBB.getXCV();
            assertNotNull(xcv);

            subXCVs = xcv.getSubXCV();
            if (subXCVs.size() == 2) {
                assertEquals(Indication.PASSED, xcv.getConclusion().getIndication());
                assertTrue(checkMessageValuePresence(convert(xcv.getConclusion().getWarnings()), i18nProvider.getMessage(MessageTag.BBB_XCV_HPCCVVT_ANS)));
                signatureTstFound = true;
            }

            untrustedCertCounter = 0;
            trustedCertCounter = 0;
            for (XmlSubXCV subXCV : subXCVs) {
                if (subXCV.isTrustAnchor()) {
                    if (subXCVs.size() == 2) {
                        // sig tst
                        assertEquals(Indication.PASSED, subXCV.getConclusion().getIndication());
                        assertTrue(checkMessageValuePresence(convert(subXCV.getConclusion().getWarnings()), i18nProvider.getMessage(MessageTag.BBB_XCV_IOTAA_ANS)));
                        assertTrue(checkMessageValuePresence(convert(subXCV.getConclusion().getWarnings()), i18nProvider.getMessage(MessageTag.BBB_XCV_IVTBCTSD_ANS)));

                        boolean validationTimeCheckFound = false;
                        boolean validProspectiveChainCheckFound = false;
                        for (XmlConstraint xmlConstraint : subXCV.getConstraint()) {
                            if (MessageTag.BBB_XCV_IVTBCTSD.getId().equals(xmlConstraint.getName().getKey())) {
                                assertEquals(XmlStatus.WARNING, xmlConstraint.getStatus());
                                assertEquals(MessageTag.BBB_XCV_IVTBCTSD_ANS.getId(), xmlConstraint.getWarning().getKey());
                                assertEquals(i18nProvider.getMessage(MessageTag.CERTIFICATE_SUNSET_DATE,
                                        ValidationProcessUtils.getFormattedDate(xmlDiagnosticData.getValidationDate()),
                                        ValidationProcessUtils.getFormattedDate(diagnosticData.getCertificateById(subXCV.getId()).getTrustSunsetDate())), xmlConstraint.getAdditionalInfo());
                                validationTimeCheckFound = true;
                            } else if (MessageTag.BBB_XCV_IOTAA.getId().equals(xmlConstraint.getName().getKey())) {
                                assertEquals(XmlStatus.WARNING, xmlConstraint.getStatus());
                                assertEquals(MessageTag.BBB_XCV_IOTAA_ANS.getId(), xmlConstraint.getWarning().getKey());
                                validProspectiveChainCheckFound = true;
                            }
                        }
                        assertTrue(validationTimeCheckFound);
                        assertTrue(validProspectiveChainCheckFound);
                    } else {
                        // arc tst
                        assertEquals(Indication.PASSED, subXCV.getConclusion().getIndication());

                        boolean validationTimeCheckFound = false;
                        boolean validProspectiveChainCheckFound = false;
                        for (XmlConstraint xmlConstraint : subXCV.getConstraint()) {
                            if (MessageTag.BBB_XCV_IVTBCTSD.getId().equals(xmlConstraint.getName().getKey())) {
                                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                                assertEquals(i18nProvider.getMessage(MessageTag.CERTIFICATE_SUNSET_DATE,
                                        ValidationProcessUtils.getFormattedDate(xmlDiagnosticData.getValidationDate()),
                                        ValidationProcessUtils.getFormattedDate(diagnosticData.getCertificateById(subXCV.getId()).getTrustSunsetDate())), xmlConstraint.getAdditionalInfo());
                                validationTimeCheckFound = true;
                            } else if (MessageTag.BBB_XCV_IOTAA.getId().equals(xmlConstraint.getName().getKey())) {
                                validProspectiveChainCheckFound = true;
                            }
                        }
                        assertTrue(validationTimeCheckFound);
                        assertFalse(validProspectiveChainCheckFound);
                    }
                    ++trustedCertCounter;
                } else {
                    ++untrustedCertCounter;
                }
            }
            assertEquals(subXCVs.size() - 1, untrustedCertCounter);
            assertEquals(1, trustedCertCounter);

        }
        assertTrue(signatureTstFound);

        validateBestSigningTimes(reports);
        checkReports(reports);
    }

    @Test
    void expiredSigTstNeverExpiresTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_sunset.xml"));
        assertNotNull(xmlDiagnosticData);

        Calendar calendar = Calendar.getInstance();
        calendar.set(2026, Calendar.JANUARY, 0, 0, 0, 0);
        Date validationTime = calendar.getTime();

        xmlDiagnosticData.setValidationDate(validationTime);

        xmlDiagnosticData.getUsedTimestamps().get(1).getSigningCertificate().getCertificate().getTrusted().setSunsetDate(null);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();
        assertNotNull(reports);

        DiagnosticData diagnosticData = reports.getDiagnosticData();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId())));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationWarnings(simpleReport.getFirstSignatureId())));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationInfo(simpleReport.getFirstSignatureId())));

        String firstTstId = simpleReport.getSignatureTimestamps(simpleReport.getFirstSignatureId()).get(0).getId();
        assertEquals(Indication.PASSED, simpleReport.getIndication(firstTstId));

        DetailedReport detailedReport = reports.getDetailedReport();
        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertNotNull(signatureBBB);
        assertEquals(Indication.PASSED, signatureBBB.getConclusion().getIndication());

        XmlXCV xcv = signatureBBB.getXCV();
        assertNotNull(xcv);
        assertEquals(Indication.INDETERMINATE, xcv.getConclusion().getIndication());
        assertEquals(SubIndication.NO_CERTIFICATE_CHAIN_FOUND_NO_POE, xcv.getConclusion().getSubIndication());
        assertTrue(checkMessageValuePresence(convert(xcv.getConclusion().getErrors()), i18nProvider.getMessage(MessageTag.BBB_XCV_HPCCVVT_ANS)));

        int prospectiveChainFoundCounter = 0;
        int trustAnchorSunsetCheckValidCounter = 0;
        int trustAnchorSunsetCheckInvalidCounter = 0;
        int validProspectiveChainFoundCounter = 0;
        int invalidProspectiveChainFoundCounter = 0;
        int xmlSubXCVCheckValidCounter = 0;
        int xmlSubXCVCheckInvalidCounter = 0;

        for (XmlConstraint xmlConstraint : xcv.getConstraint()) {
            if (MessageTag.BBB_XCV_CCCBB.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                ++prospectiveChainFoundCounter;
            } else if (MessageTag.BBB_XCV_IVTBCTSD.getId().equals(xmlConstraint.getName().getKey())) {
                assertNotNull(xmlConstraint.getId());
                assertEquals(i18nProvider.getMessage(MessageTag.CERTIFICATE_SUNSET_DATE,
                                ValidationProcessUtils.getFormattedDate(xmlDiagnosticData.getValidationDate()),
                                ValidationProcessUtils.getFormattedDate(diagnosticData.getCertificateById(xmlConstraint.getId()).getTrustSunsetDate())),
                        xmlConstraint.getAdditionalInfo());
                if (XmlStatus.OK == xmlConstraint.getStatus()) {
                    ++trustAnchorSunsetCheckValidCounter;
                } else if (XmlStatus.WARNING == xmlConstraint.getStatus()) {
                    assertEquals(MessageTag.BBB_XCV_IVTBCTSD_ANS.getId(), xmlConstraint.getWarning().getKey());
                    ++trustAnchorSunsetCheckInvalidCounter;
                }
            } else if (MessageTag.BBB_XCV_HPCCVVT.getId().equals(xmlConstraint.getName().getKey())) {
                if (XmlStatus.OK == xmlConstraint.getStatus()) {
                    ++validProspectiveChainFoundCounter;
                } else if (XmlStatus.NOT_OK == xmlConstraint.getStatus()) {
                    assertEquals(MessageTag.BBB_XCV_HPCCVVT_ANS.getId(), xmlConstraint.getError().getKey());
                    ++ invalidProspectiveChainFoundCounter;
                }
            } else if (MessageTag.BBB_XCV_SUB.getId().equals(xmlConstraint.getName().getKey())) {
                assertNotNull(xmlConstraint.getId());
                if (XmlStatus.OK == xmlConstraint.getStatus()) {
                    ++xmlSubXCVCheckValidCounter;
                } else if (XmlStatus.NOT_OK == xmlConstraint.getStatus()) {
                    assertEquals(MessageTag.BBB_XCV_SUB_ANS.getId(), xmlConstraint.getError().getKey());
                    ++xmlSubXCVCheckInvalidCounter;
                }
            }
        }

        assertEquals(1, prospectiveChainFoundCounter);
        assertEquals(0, trustAnchorSunsetCheckValidCounter);
        assertEquals(1, trustAnchorSunsetCheckInvalidCounter);
        assertEquals(0, validProspectiveChainFoundCounter);
        assertEquals(1, invalidProspectiveChainFoundCounter);
        assertEquals(0, xmlSubXCVCheckValidCounter);
        assertEquals(0, xmlSubXCVCheckInvalidCounter);

        List<XmlSubXCV> subXCVs = xcv.getSubXCV();
        assertEquals(3, subXCVs.size());

        int untrustedCertCounter = 0;
        int trustedCertCounter = 0;
        for (XmlSubXCV subXCV : subXCVs) {
            if (subXCV.isTrustAnchor()) {
                assertEquals(Indication.INDETERMINATE, subXCV.getConclusion().getIndication());
                assertEquals(SubIndication.NO_CERTIFICATE_CHAIN_FOUND_NO_POE, subXCV.getConclusion().getSubIndication());
                assertTrue(checkMessageValuePresence(convert(subXCV.getConclusion().getErrors()), i18nProvider.getMessage(MessageTag.BBB_XCV_IOTAA_ANS)));

                boolean validationTimeCheckFound = false;
                boolean validProspectiveChainCheckFound = false;
                for (XmlConstraint xmlConstraint : subXCV.getConstraint()) {
                    if (MessageTag.BBB_XCV_IVTBCTSD.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.WARNING, xmlConstraint.getStatus());
                        assertEquals(MessageTag.BBB_XCV_IVTBCTSD_ANS.getId(), xmlConstraint.getWarning().getKey());
                        assertEquals(i18nProvider.getMessage(MessageTag.CERTIFICATE_SUNSET_DATE,
                                ValidationProcessUtils.getFormattedDate(xmlDiagnosticData.getValidationDate()),
                                ValidationProcessUtils.getFormattedDate(diagnosticData.getCertificateById(subXCV.getId()).getTrustSunsetDate())), xmlConstraint.getAdditionalInfo());
                        validationTimeCheckFound = true;
                    } else if (MessageTag.BBB_XCV_IOTAA.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                        assertEquals(MessageTag.BBB_XCV_IOTAA_ANS.getId(), xmlConstraint.getError().getKey());
                        validProspectiveChainCheckFound = true;
                    }
                }
                assertTrue(validationTimeCheckFound);
                assertTrue(validProspectiveChainCheckFound);
                ++trustedCertCounter;
            } else {
                ++untrustedCertCounter;
            }
        }
        assertEquals(2, untrustedCertCounter);
        assertEquals(1, trustedCertCounter);

        boolean signatureTstFound = false;
        boolean archiveTstFound = false;
        for (String timestampId : diagnosticData.getTimestampIdList()) {
            XmlBasicBuildingBlocks timestampBBB = detailedReport.getBasicBuildingBlockById(timestampId);

            xcv = timestampBBB.getXCV();
            assertNotNull(xcv);

            subXCVs = xcv.getSubXCV();
            if (subXCVs.size() == 2) {
                assertEquals(Indication.INDETERMINATE, xcv.getConclusion().getIndication());
                assertEquals(SubIndication.NO_CERTIFICATE_CHAIN_FOUND_NO_POE, xcv.getConclusion().getSubIndication());
                assertTrue(checkMessageValuePresence(convert(xcv.getConclusion().getErrors()), i18nProvider.getMessage(MessageTag.BBB_XCV_HPCCVVT_ANS)));
                signatureTstFound = true;
            } else if (subXCVs.size() == 1) {
                assertEquals(Indication.PASSED, xcv.getConclusion().getIndication());
                archiveTstFound = true;
            }

            untrustedCertCounter = 0;
            trustedCertCounter = 0;
            for (XmlSubXCV subXCV : subXCVs) {
                if (subXCV.isTrustAnchor()) {
                    if (subXCVs.size() == 2) {
                        // sig tst
                        assertEquals(Indication.INDETERMINATE, subXCV.getConclusion().getIndication());
                        assertEquals(SubIndication.NO_CERTIFICATE_CHAIN_FOUND_NO_POE, subXCV.getConclusion().getSubIndication());
                        assertTrue(checkMessageValuePresence(convert(subXCV.getConclusion().getErrors()), i18nProvider.getMessage(MessageTag.BBB_XCV_IOTAA_ANS)));

                        boolean validationTimeCheckFound = false;
                        boolean validProspectiveChainCheckFound = false;
                        for (XmlConstraint xmlConstraint : subXCV.getConstraint()) {
                            if (MessageTag.BBB_XCV_IVTBCTSD.getId().equals(xmlConstraint.getName().getKey())) {
                                assertEquals(XmlStatus.WARNING, xmlConstraint.getStatus());
                                assertEquals(MessageTag.BBB_XCV_IVTBCTSD_ANS.getId(), xmlConstraint.getWarning().getKey());
                                assertEquals(i18nProvider.getMessage(MessageTag.CERTIFICATE_SUNSET_DATE,
                                        ValidationProcessUtils.getFormattedDate(xmlDiagnosticData.getValidationDate()),
                                        ValidationProcessUtils.getFormattedDate(diagnosticData.getCertificateById(subXCV.getId()).getTrustSunsetDate())), xmlConstraint.getAdditionalInfo());
                                validationTimeCheckFound = true;
                            } else if (MessageTag.BBB_XCV_IOTAA.getId().equals(xmlConstraint.getName().getKey())) {
                                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                                assertEquals(MessageTag.BBB_XCV_IOTAA_ANS.getId(), xmlConstraint.getError().getKey());
                                validProspectiveChainCheckFound = true;
                            }
                        }
                        assertTrue(validationTimeCheckFound);
                        assertTrue(validProspectiveChainCheckFound);
                    } else {
                        // arc tst
                        assertEquals(Indication.PASSED, subXCV.getConclusion().getIndication());

                        boolean validationTimeCheckFound = false;
                        boolean validProspectiveChainCheckFound = false;
                        for (XmlConstraint xmlConstraint : subXCV.getConstraint()) {
                            if (MessageTag.BBB_XCV_IVTBCTSD.getId().equals(xmlConstraint.getName().getKey())) {
                                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                                assertEquals(i18nProvider.getMessage(MessageTag.CERTIFICATE_SUNSET_DATE_VALID), xmlConstraint.getAdditionalInfo());
                                validationTimeCheckFound = true;
                            } else if (MessageTag.BBB_XCV_IOTAA.getId().equals(xmlConstraint.getName().getKey())) {
                                validProspectiveChainCheckFound = true;
                            }
                        }
                        assertTrue(validationTimeCheckFound);
                        assertFalse(validProspectiveChainCheckFound);
                    }
                    ++trustedCertCounter;
                } else {
                    ++untrustedCertCounter;
                }
            }
            assertEquals(subXCVs.size() - 1, untrustedCertCounter);
            assertEquals(1, trustedCertCounter);

        }
        assertTrue(signatureTstFound);
        assertTrue(archiveTstFound);

        validateBestSigningTimes(reports);
        checkReports(reports);
    }

    @Test
    void expiredSignCertTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_sunset.xml"));
        assertNotNull(xmlDiagnosticData);

        Calendar calendar = Calendar.getInstance();
        calendar.set(2023, Calendar.JANUARY, 0, 0, 0, 0);
        Date validationTime = calendar.getTime();

        xmlDiagnosticData.setValidationDate(validationTime);

        calendar.set(2021, Calendar.JANUARY, 0, 0, 0, 0);
        Date certNotAfter = calendar.getTime();

        xmlDiagnosticData.getSignatures().get(0).getSigningCertificate().getCertificate().setNotAfter(certNotAfter);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();
        assertNotNull(reports);

        DiagnosticData diagnosticData = reports.getDiagnosticData();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.OUT_OF_BOUNDS_NO_POE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.TSV_ISCNVABST_ANS)));

        String firstTstId = simpleReport.getSignatureTimestamps(simpleReport.getFirstSignatureId()).get(0).getId();
        assertEquals(Indication.PASSED, simpleReport.getIndication(firstTstId));

        DetailedReport detailedReport = reports.getDetailedReport();
        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertNotNull(signatureBBB);
        assertEquals(Indication.INDETERMINATE, signatureBBB.getConclusion().getIndication());
        assertEquals(SubIndication.OUT_OF_BOUNDS_NO_POE, signatureBBB.getConclusion().getSubIndication());

        XmlXCV xcv = signatureBBB.getXCV();
        assertNotNull(xcv);
        assertEquals(Indication.INDETERMINATE, xcv.getConclusion().getIndication());
        assertEquals(SubIndication.NO_CERTIFICATE_CHAIN_FOUND_NO_POE, xcv.getConclusion().getSubIndication());
        assertTrue(checkMessageValuePresence(convert(xcv.getConclusion().getErrors()), i18nProvider.getMessage(MessageTag.BBB_XCV_ICTIVRSC_ANS)));
        assertTrue(checkMessageValuePresence(convert(xcv.getConclusion().getErrors()), i18nProvider.getMessage(MessageTag.BBB_XCV_HPCCVVT_ANS)));

        int prospectiveChainFoundCounter = 0;
        int trustAnchorSunsetCheckValidCounter = 0;
        int trustAnchorSunsetCheckInvalidCounter = 0;
        int validProspectiveChainFoundCounter = 0;
        int invalidProspectiveChainFoundCounter = 0;
        int xmlSubXCVCheckValidCounter = 0;
        int xmlSubXCVCheckInvalidCounter = 0;

        for (XmlConstraint xmlConstraint : xcv.getConstraint()) {
            if (MessageTag.BBB_XCV_CCCBB.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                ++prospectiveChainFoundCounter;
            } else if (MessageTag.BBB_XCV_IVTBCTSD.getId().equals(xmlConstraint.getName().getKey())) {
                assertNotNull(xmlConstraint.getId());
                assertEquals(i18nProvider.getMessage(MessageTag.CERTIFICATE_SUNSET_DATE,
                                ValidationProcessUtils.getFormattedDate(xmlDiagnosticData.getValidationDate()),
                                ValidationProcessUtils.getFormattedDate(diagnosticData.getCertificateById(xmlConstraint.getId()).getTrustSunsetDate())),
                        xmlConstraint.getAdditionalInfo());
                if (XmlStatus.OK == xmlConstraint.getStatus()) {
                    ++trustAnchorSunsetCheckValidCounter;
                } else if (XmlStatus.WARNING == xmlConstraint.getStatus()) {
                    assertEquals(MessageTag.BBB_XCV_IVTBCTSD_ANS.getId(), xmlConstraint.getWarning().getKey());
                    ++trustAnchorSunsetCheckInvalidCounter;
                }
            } else if (MessageTag.BBB_XCV_HPCCVVT.getId().equals(xmlConstraint.getName().getKey())) {
                if (XmlStatus.OK == xmlConstraint.getStatus()) {
                    ++validProspectiveChainFoundCounter;
                } else if (XmlStatus.NOT_OK == xmlConstraint.getStatus()) {
                    assertEquals(MessageTag.BBB_XCV_HPCCVVT_ANS.getId(), xmlConstraint.getError().getKey());
                    ++ invalidProspectiveChainFoundCounter;
                }
            } else if (MessageTag.BBB_XCV_SUB.getId().equals(xmlConstraint.getName().getKey())) {
                assertNotNull(xmlConstraint.getId());
                if (XmlStatus.OK == xmlConstraint.getStatus()) {
                    ++xmlSubXCVCheckValidCounter;
                } else if (XmlStatus.NOT_OK == xmlConstraint.getStatus()) {
                    assertEquals(MessageTag.BBB_XCV_SUB_ANS.getId(), xmlConstraint.getError().getKey());
                    ++xmlSubXCVCheckInvalidCounter;
                }
            }
        }

        assertEquals(1, prospectiveChainFoundCounter);
        assertEquals(0, trustAnchorSunsetCheckValidCounter);
        assertEquals(1, trustAnchorSunsetCheckInvalidCounter);
        assertEquals(0, validProspectiveChainFoundCounter);
        assertEquals(1, invalidProspectiveChainFoundCounter);
        assertEquals(0, xmlSubXCVCheckValidCounter);
        assertEquals(0, xmlSubXCVCheckInvalidCounter);

        List<XmlSubXCV> subXCVs = xcv.getSubXCV();
        assertEquals(3, subXCVs.size());

        int untrustedCertValidCounter = 0;
        int untrustedCertInvalidCounter = 0;
        int trustedCertCounter = 0;
        for (XmlSubXCV subXCV : subXCVs) {
            if (subXCV.isTrustAnchor()) {
                assertEquals(Indication.INDETERMINATE, subXCV.getConclusion().getIndication());
                assertEquals(SubIndication.NO_CERTIFICATE_CHAIN_FOUND_NO_POE, subXCV.getConclusion().getSubIndication());
                assertTrue(checkMessageValuePresence(convert(subXCV.getConclusion().getErrors()), i18nProvider.getMessage(MessageTag.BBB_XCV_IOTAA_ANS)));
                assertTrue(checkMessageValuePresence(convert(subXCV.getConclusion().getWarnings()), i18nProvider.getMessage(MessageTag.BBB_XCV_IVTBCTSD_ANS)));

                boolean validationTimeCheckFound = false;
                boolean validProspectiveChainCheckFound = false;
                for (XmlConstraint xmlConstraint : subXCV.getConstraint()) {
                    if (MessageTag.BBB_XCV_IVTBCTSD.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.WARNING, xmlConstraint.getStatus());
                        assertEquals(MessageTag.BBB_XCV_IVTBCTSD_ANS.getId(), xmlConstraint.getWarning().getKey());
                        assertEquals(i18nProvider.getMessage(MessageTag.CERTIFICATE_SUNSET_DATE,
                                ValidationProcessUtils.getFormattedDate(xmlDiagnosticData.getValidationDate()),
                                ValidationProcessUtils.getFormattedDate(diagnosticData.getCertificateById(subXCV.getId()).getTrustSunsetDate())), xmlConstraint.getAdditionalInfo());
                        validationTimeCheckFound = true;
                    } else if (MessageTag.BBB_XCV_IOTAA.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                        assertEquals(MessageTag.BBB_XCV_IOTAA_ANS.getId(), xmlConstraint.getError().getKey());
                        validProspectiveChainCheckFound = true;
                    }
                }
                assertTrue(validationTimeCheckFound);
                assertTrue(validProspectiveChainCheckFound);
                ++trustedCertCounter;
            } else {
                if (Indication.PASSED.equals(subXCV.getConclusion().getIndication())) {
                    ++untrustedCertValidCounter;
                } else if (Indication.INDETERMINATE.equals(subXCV.getConclusion().getIndication())) {
                    assertEquals(SubIndication.OUT_OF_BOUNDS_NO_POE, subXCV.getConclusion().getSubIndication());
                    ++untrustedCertInvalidCounter;
                }
            }
        }
        assertEquals(1, untrustedCertValidCounter);
        assertEquals(1, untrustedCertInvalidCounter);
        assertEquals(1, trustedCertCounter);

        XmlPSV psv = signatureBBB.getPSV();
        assertNotNull(psv);
        assertEquals(Indication.INDETERMINATE, psv.getConclusion().getIndication());
        assertEquals(SubIndication.OUT_OF_BOUNDS_NO_POE, psv.getConclusion().getSubIndication());
        assertTrue(checkMessageValuePresence(convert(psv.getConclusion().getErrors()), i18nProvider.getMessage(MessageTag.TSV_ISCNVABST_ANS)));

        boolean pastCertValidationCheckFound = false;
        boolean validityRangeCheckFound = false;
        for (XmlConstraint xmlConstraint : psv.getConstraint()) {
            if (MessageTag.PSV_IPCVA.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                pastCertValidationCheckFound = true;
            } else if (MessageTag.TSV_ISCNVABST.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                assertEquals(MessageTag.TSV_ISCNVABST_ANS.getId(), xmlConstraint.getError().getKey());
                validityRangeCheckFound = true;
            }
        }
        assertTrue(pastCertValidationCheckFound);
        assertTrue(validityRangeCheckFound);

        boolean signatureTstFound = false;
        boolean archiveTstFound = false;
        for (String timestampId : diagnosticData.getTimestampIdList()) {
            XmlBasicBuildingBlocks timestampBBB = detailedReport.getBasicBuildingBlockById(timestampId);

            xcv = timestampBBB.getXCV();
            assertNotNull(xcv);

            subXCVs = xcv.getSubXCV();
            if (subXCVs.size() == 2) {
                assertEquals(Indication.INDETERMINATE, xcv.getConclusion().getIndication());
                assertEquals(SubIndication.NO_CERTIFICATE_CHAIN_FOUND_NO_POE, xcv.getConclusion().getSubIndication());
                assertTrue(checkMessageValuePresence(convert(xcv.getConclusion().getErrors()), i18nProvider.getMessage(MessageTag.BBB_XCV_ICTIVRSC_ANS)));
                assertTrue(checkMessageValuePresence(convert(xcv.getConclusion().getErrors()), i18nProvider.getMessage(MessageTag.BBB_XCV_HPCCVVT_ANS)));
                signatureTstFound = true;
            } else if (subXCVs.size() == 1) {
                assertEquals(Indication.PASSED, xcv.getConclusion().getIndication());
                archiveTstFound = true;
            }

            untrustedCertValidCounter = 0;
            untrustedCertInvalidCounter = 0;
            trustedCertCounter = 0;
            for (XmlSubXCV subXCV : subXCVs) {
                if (subXCV.isTrustAnchor()) {
                    if (subXCVs.size() == 2) {
                        // sig tst
                        assertEquals(Indication.INDETERMINATE, subXCV.getConclusion().getIndication());
                        assertEquals(SubIndication.NO_CERTIFICATE_CHAIN_FOUND_NO_POE, subXCV.getConclusion().getSubIndication());
                        assertTrue(checkMessageValuePresence(convert(subXCV.getConclusion().getErrors()), i18nProvider.getMessage(MessageTag.BBB_XCV_IOTAA_ANS)));
                        assertTrue(checkMessageValuePresence(convert(subXCV.getConclusion().getWarnings()), i18nProvider.getMessage(MessageTag.BBB_XCV_IVTBCTSD_ANS)));

                        boolean validationTimeCheckFound = false;
                        boolean validProspectiveChainCheckFound = false;
                        for (XmlConstraint xmlConstraint : subXCV.getConstraint()) {
                            if (MessageTag.BBB_XCV_IVTBCTSD.getId().equals(xmlConstraint.getName().getKey())) {
                                assertEquals(XmlStatus.WARNING, xmlConstraint.getStatus());
                                assertEquals(MessageTag.BBB_XCV_IVTBCTSD_ANS.getId(), xmlConstraint.getWarning().getKey());
                                assertEquals(i18nProvider.getMessage(MessageTag.CERTIFICATE_SUNSET_DATE,
                                        ValidationProcessUtils.getFormattedDate(xmlDiagnosticData.getValidationDate()),
                                        ValidationProcessUtils.getFormattedDate(diagnosticData.getCertificateById(subXCV.getId()).getTrustSunsetDate())), xmlConstraint.getAdditionalInfo());
                                validationTimeCheckFound = true;
                            } else if (MessageTag.BBB_XCV_IOTAA.getId().equals(xmlConstraint.getName().getKey())) {
                                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                                assertEquals(MessageTag.BBB_XCV_IOTAA_ANS.getId(), xmlConstraint.getError().getKey());
                                validProspectiveChainCheckFound = true;
                            }
                        }
                        assertTrue(validationTimeCheckFound);
                        assertTrue(validProspectiveChainCheckFound);
                    } else {
                        // arc tst
                        assertEquals(Indication.PASSED, subXCV.getConclusion().getIndication());

                        boolean validationTimeCheckFound = false;
                        boolean validProspectiveChainCheckFound = false;
                        for (XmlConstraint xmlConstraint : subXCV.getConstraint()) {
                            if (MessageTag.BBB_XCV_IVTBCTSD.getId().equals(xmlConstraint.getName().getKey())) {
                                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                                assertEquals(i18nProvider.getMessage(MessageTag.CERTIFICATE_SUNSET_DATE,
                                        ValidationProcessUtils.getFormattedDate(xmlDiagnosticData.getValidationDate()),
                                        ValidationProcessUtils.getFormattedDate(diagnosticData.getCertificateById(subXCV.getId()).getTrustSunsetDate())), xmlConstraint.getAdditionalInfo());
                                validationTimeCheckFound = true;
                            } else if (MessageTag.BBB_XCV_IOTAA.getId().equals(xmlConstraint.getName().getKey())) {
                                validProspectiveChainCheckFound = true;
                            }
                        }
                        assertTrue(validationTimeCheckFound);
                        assertFalse(validProspectiveChainCheckFound);
                    }
                    ++trustedCertCounter;
                } else {
                    if (Indication.PASSED.equals(subXCV.getConclusion().getIndication())) {
                        ++untrustedCertValidCounter;
                    } else {
                        ++untrustedCertInvalidCounter;
                    }
                }
            }
            assertEquals(0, untrustedCertValidCounter);
            assertEquals(subXCVs.size() - 1, untrustedCertInvalidCounter);
            assertEquals(1, trustedCertCounter);

        }
        assertTrue(signatureTstFound);
        assertTrue(archiveTstFound);

        validateBestSigningTimes(reports);
        checkReports(reports);
    }

    @Test
    void twoTrustAnchorsTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_sunset_multiple_trust_anchors.xml"));
        assertNotNull(xmlDiagnosticData);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();
        assertNotNull(reports);

        DiagnosticData diagnosticData = reports.getDiagnosticData();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId())));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationWarnings(simpleReport.getFirstSignatureId())));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationInfo(simpleReport.getFirstSignatureId())));

        String firstTstId = simpleReport.getSignatureTimestamps(simpleReport.getFirstSignatureId()).get(0).getId();
        assertEquals(Indication.PASSED, simpleReport.getIndication(firstTstId));

        DetailedReport detailedReport = reports.getDetailedReport();
        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertNotNull(signatureBBB);
        assertEquals(Indication.PASSED, signatureBBB.getConclusion().getIndication());

        XmlXCV xcv = signatureBBB.getXCV();
        assertNotNull(xcv);
        assertEquals(Indication.PASSED, xcv.getConclusion().getIndication());
        assertTrue(Utils.isCollectionEmpty(xcv.getConclusion().getErrors()));
        assertTrue(Utils.isCollectionEmpty(xcv.getConclusion().getWarnings()));
        assertTrue(Utils.isCollectionEmpty(xcv.getConclusion().getInfos()));

        int prospectiveChainFoundCounter = 0;
        int trustAnchorSunsetCheckValidCounter = 0;
        int trustAnchorSunsetCheckInvalidCounter = 0;
        int validProspectiveChainFoundCounter = 0;
        int invalidProspectiveChainFoundCounter = 0;
        int xmlSubXCVCheckValidCounter = 0;
        int xmlSubXCVCheckInvalidCounter = 0;

        for (XmlConstraint xmlConstraint : xcv.getConstraint()) {
            if (MessageTag.BBB_XCV_CCCBB.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                ++prospectiveChainFoundCounter;
            } else if (MessageTag.BBB_XCV_IVTBCTSD.getId().equals(xmlConstraint.getName().getKey())) {
                assertNotNull(xmlConstraint.getId());
                assertEquals(i18nProvider.getMessage(MessageTag.CERTIFICATE_SUNSET_DATE,
                                ValidationProcessUtils.getFormattedDate(xmlDiagnosticData.getValidationDate()),
                                ValidationProcessUtils.getFormattedDate(diagnosticData.getCertificateById(xmlConstraint.getId()).getTrustSunsetDate())),
                        xmlConstraint.getAdditionalInfo());
                if (XmlStatus.OK == xmlConstraint.getStatus()) {
                    ++trustAnchorSunsetCheckValidCounter;
                } else if (XmlStatus.WARNING == xmlConstraint.getStatus()) {
                    assertEquals(MessageTag.BBB_XCV_IVTBCTSD_ANS.getId(), xmlConstraint.getWarning().getKey());
                    ++trustAnchorSunsetCheckInvalidCounter;
                }
            } else if (MessageTag.BBB_XCV_HPCCVVT.getId().equals(xmlConstraint.getName().getKey())) {
                if (XmlStatus.OK == xmlConstraint.getStatus()) {
                    ++validProspectiveChainFoundCounter;
                } else if (XmlStatus.NOT_OK == xmlConstraint.getStatus()) {
                    assertEquals(MessageTag.BBB_XCV_HPCCVVT_ANS.getId(), xmlConstraint.getError().getKey());
                    ++ invalidProspectiveChainFoundCounter;
                }
            } else if (MessageTag.BBB_XCV_SUB.getId().equals(xmlConstraint.getName().getKey())) {
                assertNotNull(xmlConstraint.getId());
                if (XmlStatus.OK == xmlConstraint.getStatus()) {
                    ++xmlSubXCVCheckValidCounter;
                } else if (XmlStatus.NOT_OK == xmlConstraint.getStatus()) {
                    assertEquals(MessageTag.BBB_XCV_SUB_ANS.getId(), xmlConstraint.getError().getKey());
                    ++xmlSubXCVCheckInvalidCounter;
                }
            }
        }

        assertEquals(1, prospectiveChainFoundCounter);
        assertEquals(1, trustAnchorSunsetCheckValidCounter);
        assertEquals(0, trustAnchorSunsetCheckInvalidCounter);
        assertEquals(1, validProspectiveChainFoundCounter);
        assertEquals(0, invalidProspectiveChainFoundCounter);
        assertEquals(2, xmlSubXCVCheckValidCounter);
        assertEquals(0, xmlSubXCVCheckInvalidCounter);

        List<XmlSubXCV> subXCVs = xcv.getSubXCV();
        assertEquals(2, subXCVs.size());

        int untrustedCertCounter = 0;
        int trustedCertCounter = 0;
        for (XmlSubXCV subXCV : subXCVs) {
            if (subXCV.isTrustAnchor()) {
                assertEquals(1, subXCV.getConstraint().size());
                assertEquals(MessageTag.BBB_XCV_IVTBCTSD.getId(), subXCV.getConstraint().get(0).getName().getKey());
                assertEquals(XmlStatus.OK, subXCV.getConstraint().get(0).getStatus());
                assertEquals(i18nProvider.getMessage(MessageTag.CERTIFICATE_SUNSET_DATE,
                                ValidationProcessUtils.getFormattedDate(xmlDiagnosticData.getValidationDate()),
                                ValidationProcessUtils.getFormattedDate(diagnosticData.getCertificateById(subXCV.getId()).getTrustSunsetDate())),
                        subXCV.getConstraint().get(0).getAdditionalInfo());
                ++trustedCertCounter;
            } else {
                ++untrustedCertCounter;
            }
        }
        assertEquals(1, untrustedCertCounter);
        assertEquals(1, trustedCertCounter);

        XmlBasicBuildingBlocks timestampBBB = detailedReport.getBasicBuildingBlockById(firstTstId);

        xcv = timestampBBB.getXCV();
        assertNotNull(xcv);
        assertEquals(Indication.PASSED, xcv.getConclusion().getIndication());
        subXCVs = xcv.getSubXCV();

        untrustedCertCounter = 0;
        trustedCertCounter = 0;
        for (XmlSubXCV subXCV : subXCVs) {
            if (subXCV.isTrustAnchor()) {
                assertEquals(1, subXCV.getConstraint().size());
                assertEquals(MessageTag.BBB_XCV_IVTBCTSD.getId(), subXCV.getConstraint().get(0).getName().getKey());
                assertEquals(XmlStatus.OK, subXCV.getConstraint().get(0).getStatus());
                assertEquals(i18nProvider.getMessage(MessageTag.CERTIFICATE_SUNSET_DATE,
                                ValidationProcessUtils.getFormattedDate(xmlDiagnosticData.getValidationDate()),
                                ValidationProcessUtils.getFormattedDate(diagnosticData.getCertificateById(subXCV.getId()).getTrustSunsetDate())),
                        subXCV.getConstraint().get(0).getAdditionalInfo());
                ++trustedCertCounter;
            } else {
                ++untrustedCertCounter;
            }
        }
        assertEquals(subXCVs.size() - 1, untrustedCertCounter);
        assertEquals(1, trustedCertCounter);

        validateBestSigningTimes(reports);
        checkReports(reports);
    }

    @Test
    void twoTrustAnchorsFirstExpiredTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_sunset_multiple_trust_anchors.xml"));
        assertNotNull(xmlDiagnosticData);

        Calendar calendar = Calendar.getInstance();
        calendar.set(2023, Calendar.JANUARY, 1, 0, 0, 0);
        Date validationTime = calendar.getTime();

        xmlDiagnosticData.setValidationDate(validationTime);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();
        assertNotNull(reports);

        DiagnosticData diagnosticData = reports.getDiagnosticData();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId())));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationWarnings(simpleReport.getFirstSignatureId())));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationInfo(simpleReport.getFirstSignatureId())));

        String firstTstId = simpleReport.getSignatureTimestamps(simpleReport.getFirstSignatureId()).get(0).getId();
        assertEquals(Indication.PASSED, simpleReport.getIndication(firstTstId));

        DetailedReport detailedReport = reports.getDetailedReport();
        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertNotNull(signatureBBB);
        assertEquals(Indication.PASSED, signatureBBB.getConclusion().getIndication());

        XmlXCV xcv = signatureBBB.getXCV();
        assertNotNull(xcv);
        assertEquals(Indication.PASSED, xcv.getConclusion().getIndication());
        assertTrue(Utils.isCollectionEmpty(xcv.getConclusion().getErrors()));
        assertTrue(Utils.isCollectionEmpty(xcv.getConclusion().getWarnings()));
        assertTrue(Utils.isCollectionEmpty(xcv.getConclusion().getInfos()));

        int prospectiveChainFoundCounter = 0;
        int trustAnchorSunsetCheckValidCounter = 0;
        int trustAnchorSunsetCheckInvalidCounter = 0;
        int validProspectiveChainFoundCounter = 0;
        int invalidProspectiveChainFoundCounter = 0;
        int xmlSubXCVCheckValidCounter = 0;
        int xmlSubXCVCheckInvalidCounter = 0;

        for (XmlConstraint xmlConstraint : xcv.getConstraint()) {
            if (MessageTag.BBB_XCV_CCCBB.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                ++prospectiveChainFoundCounter;
            } else if (MessageTag.BBB_XCV_IVTBCTSD.getId().equals(xmlConstraint.getName().getKey())) {
                assertNotNull(xmlConstraint.getId());
                assertEquals(i18nProvider.getMessage(MessageTag.CERTIFICATE_SUNSET_DATE,
                                ValidationProcessUtils.getFormattedDate(xmlDiagnosticData.getValidationDate()),
                                ValidationProcessUtils.getFormattedDate(diagnosticData.getCertificateById(xmlConstraint.getId()).getTrustSunsetDate())),
                        xmlConstraint.getAdditionalInfo());
                if (XmlStatus.OK == xmlConstraint.getStatus()) {
                    ++trustAnchorSunsetCheckValidCounter;
                } else if (XmlStatus.WARNING == xmlConstraint.getStatus()) {
                    assertEquals(MessageTag.BBB_XCV_IVTBCTSD_ANS.getId(), xmlConstraint.getWarning().getKey());
                    ++trustAnchorSunsetCheckInvalidCounter;
                }
            } else if (MessageTag.BBB_XCV_HPCCVVT.getId().equals(xmlConstraint.getName().getKey())) {
                if (XmlStatus.OK == xmlConstraint.getStatus()) {
                    ++validProspectiveChainFoundCounter;
                } else if (XmlStatus.NOT_OK == xmlConstraint.getStatus()) {
                    assertEquals(MessageTag.BBB_XCV_HPCCVVT_ANS.getId(), xmlConstraint.getError().getKey());
                    ++ invalidProspectiveChainFoundCounter;
                }
            } else if (MessageTag.BBB_XCV_SUB.getId().equals(xmlConstraint.getName().getKey())) {
                assertNotNull(xmlConstraint.getId());
                if (XmlStatus.OK == xmlConstraint.getStatus()) {
                    ++xmlSubXCVCheckValidCounter;
                } else if (XmlStatus.NOT_OK == xmlConstraint.getStatus()) {
                    assertEquals(MessageTag.BBB_XCV_SUB_ANS.getId(), xmlConstraint.getError().getKey());
                    ++xmlSubXCVCheckInvalidCounter;
                }
            }
        }

        assertEquals(1, prospectiveChainFoundCounter);
        assertEquals(1, trustAnchorSunsetCheckValidCounter);
        assertEquals(1, trustAnchorSunsetCheckInvalidCounter);
        assertEquals(1, validProspectiveChainFoundCounter);
        assertEquals(0, invalidProspectiveChainFoundCounter);
        assertEquals(3, xmlSubXCVCheckValidCounter);
        assertEquals(0, xmlSubXCVCheckInvalidCounter);

        List<XmlSubXCV> subXCVs = xcv.getSubXCV();
        assertEquals(3, subXCVs.size());

        int untrustedCertCounter = 0;
        int trustedCertValidCounter = 0;
        int trustedCertInvalidCounter = 0;
        for (XmlSubXCV subXCV : subXCVs) {
            if (subXCV.isTrustAnchor()) {
                boolean sunsetCheckFound = false;
                for (XmlConstraint xmlConstraint : subXCV.getConstraint()) {
                    if (MessageTag.BBB_XCV_IVTBCTSD.getId().equals(xmlConstraint.getName().getKey())) {
                        if (XmlStatus.OK.equals(xmlConstraint.getStatus())) {
                            assertEquals(1, Utils.collectionSize(subXCV.getConstraint()));
                            ++trustedCertValidCounter;
                        } else if (XmlStatus.WARNING.equals(xmlConstraint.getStatus())) {
                            assertEquals(MessageTag.BBB_XCV_IVTBCTSD_ANS.getId(), xmlConstraint.getWarning().getKey());
                            assertEquals(i18nProvider.getMessage(MessageTag.CERTIFICATE_SUNSET_DATE,
                                            ValidationProcessUtils.getFormattedDate(xmlDiagnosticData.getValidationDate()),
                                            ValidationProcessUtils.getFormattedDate(diagnosticData.getCertificateById(subXCV.getId()).getTrustSunsetDate())),
                                    subXCV.getConstraint().get(0).getAdditionalInfo());
                            assertTrue(Utils.collectionSize(subXCV.getConstraint()) > 1);
                            ++trustedCertInvalidCounter;
                        }
                        sunsetCheckFound = true;
                    } else {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                    }
                }
                assertTrue(sunsetCheckFound);
            } else {
                ++untrustedCertCounter;
            }
        }
        assertEquals(1, untrustedCertCounter);
        assertEquals(1, trustedCertValidCounter);
        assertEquals(1, trustedCertInvalidCounter);

        XmlBasicBuildingBlocks timestampBBB = detailedReport.getBasicBuildingBlockById(firstTstId);

        xcv = timestampBBB.getXCV();
        assertNotNull(xcv);
        assertEquals(Indication.PASSED, xcv.getConclusion().getIndication());
        subXCVs = xcv.getSubXCV();

        untrustedCertCounter = 0;
        int trustedCertCounter = 0;
        for (XmlSubXCV subXCV : subXCVs) {
            if (subXCV.isTrustAnchor()) {
                assertEquals(1, subXCV.getConstraint().size());
                assertEquals(MessageTag.BBB_XCV_IVTBCTSD.getId(), subXCV.getConstraint().get(0).getName().getKey());
                assertEquals(XmlStatus.OK, subXCV.getConstraint().get(0).getStatus());
                assertEquals(i18nProvider.getMessage(MessageTag.CERTIFICATE_SUNSET_DATE,
                                ValidationProcessUtils.getFormattedDate(xmlDiagnosticData.getValidationDate()),
                                ValidationProcessUtils.getFormattedDate(diagnosticData.getCertificateById(subXCV.getId()).getTrustSunsetDate())),
                        subXCV.getConstraint().get(0).getAdditionalInfo());
                ++trustedCertCounter;
            } else {
                ++untrustedCertCounter;
            }
        }
        assertEquals(subXCVs.size() - 1, untrustedCertCounter);
        assertEquals(1, trustedCertCounter);

        validateBestSigningTimes(reports);
        checkReports(reports);
    }

    @Test
    void twoTrustAnchorsFirstExpiredAndRevokedAfterBSTTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_sunset_multiple_trust_anchors.xml"));
        assertNotNull(xmlDiagnosticData);

        Calendar calendar = Calendar.getInstance();
        calendar.set(2023, Calendar.JANUARY, 1, 0, 0, 0);
        Date validationTime = calendar.getTime();

        xmlDiagnosticData.setValidationDate(validationTime);

        calendar.set(2022, Calendar.FEBRUARY, 1, 0, 0, 0);
        Date revocationTime = calendar.getTime();

        XmlCertificate caCertificate = xmlDiagnosticData.getSignatures().get(0).getCertificateChain().get(1).getCertificate();
        XmlCertificateRevocation xmlCertificateRevocation = caCertificate.getRevocations().get(0);
        xmlCertificateRevocation.setStatus(CertificateStatus.REVOKED);
        xmlCertificateRevocation.setReason(RevocationReason.CA_COMPROMISE);
        xmlCertificateRevocation.setRevocationDate(revocationTime);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();
        assertNotNull(reports);

        DiagnosticData diagnosticData = reports.getDiagnosticData();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.NO_CERTIFICATE_CHAIN_FOUND_NO_POE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_XCV_SUB_ANS_2)));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_XCV_ISCR_ANS)));

        String firstTstId = simpleReport.getSignatureTimestamps(simpleReport.getFirstSignatureId()).get(0).getId();
        assertEquals(Indication.PASSED, simpleReport.getIndication(firstTstId));

        DetailedReport detailedReport = reports.getDetailedReport();
        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertNotNull(signatureBBB);
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.NO_CERTIFICATE_CHAIN_FOUND_NO_POE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(convert(signatureBBB.getConclusion().getErrors()), i18nProvider.getMessage(MessageTag.BBB_XCV_ISCR_ANS)));

        XmlXCV xcv = signatureBBB.getXCV();
        assertNotNull(xcv);
        assertEquals(Indication.INDETERMINATE, xcv.getConclusion().getIndication());
        assertEquals(SubIndication.NO_CERTIFICATE_CHAIN_FOUND_NO_POE, xcv.getConclusion().getSubIndication());
        assertTrue(checkMessageValuePresence(convert(xcv.getConclusion().getErrors()), i18nProvider.getMessage(MessageTag.BBB_XCV_ISCR_ANS)));

        int prospectiveChainFoundCounter = 0;
        int trustAnchorSunsetCheckValidCounter = 0;
        int trustAnchorSunsetCheckInvalidCounter = 0;
        int validProspectiveChainFoundCounter = 0;
        int invalidProspectiveChainFoundCounter = 0;
        int xmlSubXCVCheckValidCounter = 0;
        int xmlSubXCVCheckInvalidCounter = 0;

        for (XmlConstraint xmlConstraint : xcv.getConstraint()) {
            if (MessageTag.BBB_XCV_CCCBB.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                ++prospectiveChainFoundCounter;
            } else if (MessageTag.BBB_XCV_IVTBCTSD.getId().equals(xmlConstraint.getName().getKey())) {
                assertNotNull(xmlConstraint.getId());
                assertEquals(i18nProvider.getMessage(MessageTag.CERTIFICATE_SUNSET_DATE,
                                ValidationProcessUtils.getFormattedDate(xmlDiagnosticData.getValidationDate()),
                                ValidationProcessUtils.getFormattedDate(diagnosticData.getCertificateById(xmlConstraint.getId()).getTrustSunsetDate())),
                        xmlConstraint.getAdditionalInfo());
                if (XmlStatus.OK == xmlConstraint.getStatus()) {
                    ++trustAnchorSunsetCheckValidCounter;
                } else if (XmlStatus.WARNING == xmlConstraint.getStatus()) {
                    assertEquals(MessageTag.BBB_XCV_IVTBCTSD_ANS.getId(), xmlConstraint.getWarning().getKey());
                    ++trustAnchorSunsetCheckInvalidCounter;
                }
            } else if (MessageTag.BBB_XCV_HPCCVVT.getId().equals(xmlConstraint.getName().getKey())) {
                if (XmlStatus.OK == xmlConstraint.getStatus()) {
                    ++validProspectiveChainFoundCounter;
                } else if (XmlStatus.NOT_OK == xmlConstraint.getStatus()) {
                    assertEquals(MessageTag.BBB_XCV_HPCCVVT_ANS.getId(), xmlConstraint.getError().getKey());
                    ++invalidProspectiveChainFoundCounter;
                }
            } else if (MessageTag.BBB_XCV_SUB.getId().equals(xmlConstraint.getName().getKey())) {
                assertNotNull(xmlConstraint.getId());
                if (XmlStatus.OK == xmlConstraint.getStatus()) {
                    ++xmlSubXCVCheckValidCounter;
                } else if (XmlStatus.NOT_OK == xmlConstraint.getStatus()) {
                    assertEquals(MessageTag.BBB_XCV_SUB_ANS_2.getId(), xmlConstraint.getError().getKey());
                    ++xmlSubXCVCheckInvalidCounter;
                }
            }
        }

        assertEquals(1, prospectiveChainFoundCounter);
        assertEquals(1, trustAnchorSunsetCheckValidCounter);
        assertEquals(1, trustAnchorSunsetCheckInvalidCounter);
        assertEquals(1, validProspectiveChainFoundCounter);
        assertEquals(0, invalidProspectiveChainFoundCounter);
        assertEquals(1, xmlSubXCVCheckValidCounter);
        assertEquals(1, xmlSubXCVCheckInvalidCounter);

        List<XmlSubXCV> subXCVs = xcv.getSubXCV();
        assertEquals(3, subXCVs.size());

        int untrustedCertCounter = 0;
        int trustedCertValidCounter = 0;
        int trustedCertInvalidCounter = 0;
        for (XmlSubXCV subXCV : subXCVs) {
            if (subXCV.isTrustAnchor()) {
                boolean sunsetCheckFound = false;
                boolean otherProspectiveChainFound = false;
                boolean revocationCheckFound = false;
                for (XmlConstraint xmlConstraint : subXCV.getConstraint()) {
                    if (MessageTag.BBB_XCV_IVTBCTSD.getId().equals(xmlConstraint.getName().getKey())) {
                        if (XmlStatus.OK.equals(xmlConstraint.getStatus())) {
                            assertEquals(1, Utils.collectionSize(subXCV.getConstraint()));
                            ++trustedCertValidCounter;
                        } else if (XmlStatus.WARNING.equals(xmlConstraint.getStatus())) {
                            assertEquals(MessageTag.BBB_XCV_IVTBCTSD_ANS.getId(), xmlConstraint.getWarning().getKey());
                            assertEquals(i18nProvider.getMessage(MessageTag.CERTIFICATE_SUNSET_DATE,
                                            ValidationProcessUtils.getFormattedDate(xmlDiagnosticData.getValidationDate()),
                                            ValidationProcessUtils.getFormattedDate(diagnosticData.getCertificateById(subXCV.getId()).getTrustSunsetDate())),
                                    subXCV.getConstraint().get(0).getAdditionalInfo());
                            assertTrue(Utils.collectionSize(subXCV.getConstraint()) > 1);
                            ++trustedCertInvalidCounter;
                        }
                        sunsetCheckFound = true;
                    } else if (MessageTag.BBB_XCV_IOTAA.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        otherProspectiveChainFound = true;
                    } else if (MessageTag.BBB_XCV_ISCR.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                        assertEquals(MessageTag.BBB_XCV_ISCR_ANS.getId(), xmlConstraint.getError().getKey());
                        revocationCheckFound = true;
                    } else {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                    }
                }
                assertEquals(Utils.collectionSize(subXCV.getConstraint()) > 1, revocationCheckFound);
                assertEquals(Utils.collectionSize(subXCV.getConstraint()) > 1, otherProspectiveChainFound);
                assertTrue(sunsetCheckFound);
            } else {
                ++untrustedCertCounter;
            }
        }
        assertEquals(1, untrustedCertCounter);
        assertEquals(1, trustedCertValidCounter);
        assertEquals(1, trustedCertInvalidCounter);

        XmlPSV psv = signatureBBB.getPSV();
        assertNotNull(psv);
        assertEquals(Indication.INDETERMINATE, psv.getConclusion().getIndication());
        assertEquals(SubIndication.NO_CERTIFICATE_CHAIN_FOUND_NO_POE, psv.getConclusion().getSubIndication());

        boolean revocationCheckFound = false;
        boolean pastCertValFound = false;
        for (XmlConstraint xmlConstraint : psv.getConstraint()) {
            if (MessageTag.BBB_XCV_IARDPFC.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                revocationCheckFound = true;
            } else if (MessageTag.PSV_IPCVA.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                assertEquals(MessageTag.PSV_IPCVA_ANS.getId(), xmlConstraint.getError().getKey());
                assertNull(xmlConstraint.getAdditionalInfo());
                pastCertValFound = true;
            }
        }
        assertTrue(revocationCheckFound);
        assertTrue(pastCertValFound);

        XmlCRS psvcrs = signatureBBB.getPSVCRS();
        assertNotNull(psvcrs);
        assertEquals(Indication.PASSED, psvcrs.getConclusion().getIndication());

        XmlPCV pcv = signatureBBB.getPCV();
        assertNotNull(pcv);
        assertEquals(Indication.INDETERMINATE, pcv.getConclusion().getIndication());
        assertEquals(SubIndication.NO_POE, pcv.getConclusion().getSubIndication());
        assertTrue(checkMessageValuePresence(convert(pcv.getConclusion().getErrors()), i18nProvider.getMessage(MessageTag.PCV_ICCSVTSF_ANS)));

        int vtsCheckSuccessFound = 0;
        int vtsCheckFailureFound = 0;
        int certChainVtsCheckFound = 0;

        boolean firstTAFound = false;
        boolean secondTAFound = false;
        for (XmlConstraint xmlConstraint : pcv.getConstraint()) {
            if (MessageTag.PCV_IVTSC.getId().equals(xmlConstraint.getName().getKey())) {
                if (XmlStatus.OK == xmlConstraint.getStatus()) {
                    ++vtsCheckSuccessFound;
                } else if (XmlStatus.WARNING == xmlConstraint.getStatus()) {
                    if (xmlConstraint.getAdditionalInfo().equals(i18nProvider.getMessage(MessageTag.CONTROL_TIME_WITH_TRUST_ANCHOR,
                            diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId()).getCertificateChain().get(1).getId(),
                            ValidationProcessUtils.getFormattedDate(diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId()).getCertificateChain().get(1).getTrustSunsetDate())))) {
                        firstTAFound = true;
                    } else if (xmlConstraint.getAdditionalInfo().equals(i18nProvider.getMessage(MessageTag.CONTROL_TIME_WITH_TRUST_ANCHOR,
                            diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId()).getCertificateChain().get(2).getId(),
                            ValidationProcessUtils.getFormattedDate(revocationTime)))) {
                        secondTAFound = true;
                    }
                    assertEquals(MessageTag.PCV_IVTSC_ANS.getId(), xmlConstraint.getWarning().getKey());
                    ++vtsCheckFailureFound;
                }

            } else if (MessageTag.PCV_ICCSVTSF.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                assertEquals(MessageTag.PCV_ICCSVTSF_ANS.getId(), xmlConstraint.getError().getKey());
                ++certChainVtsCheckFound;
            } else {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
            }
        }
        assertEquals(0, vtsCheckSuccessFound);
        assertEquals(2, vtsCheckFailureFound);
        assertEquals(1, certChainVtsCheckFound);

        XmlVTS vts = signatureBBB.getVTS();
        assertNotNull(vts);
        assertEquals(Indication.INDETERMINATE, vts.getConclusion().getIndication());
        assertEquals(SubIndication.NO_POE, vts.getConclusion().getSubIndication());
        assertEquals(revocationTime, vts.getControlTime());
        assertEquals(diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId()).getCertificateChain().get(2).getId(), vts.getTrustAnchor());

        XmlBasicBuildingBlocks timestampBBB = detailedReport.getBasicBuildingBlockById(firstTstId);

        xcv = timestampBBB.getXCV();
        assertNotNull(xcv);
        assertEquals(Indication.PASSED, xcv.getConclusion().getIndication());
        subXCVs = xcv.getSubXCV();

        untrustedCertCounter = 0;
        int trustedCertCounter = 0;
        for (XmlSubXCV subXCV : subXCVs) {
            if (subXCV.isTrustAnchor()) {
                assertEquals(1, subXCV.getConstraint().size());
                assertEquals(MessageTag.BBB_XCV_IVTBCTSD.getId(), subXCV.getConstraint().get(0).getName().getKey());
                assertEquals(XmlStatus.OK, subXCV.getConstraint().get(0).getStatus());
                assertEquals(i18nProvider.getMessage(MessageTag.CERTIFICATE_SUNSET_DATE,
                                ValidationProcessUtils.getFormattedDate(xmlDiagnosticData.getValidationDate()),
                                ValidationProcessUtils.getFormattedDate(diagnosticData.getCertificateById(subXCV.getId()).getTrustSunsetDate())),
                        subXCV.getConstraint().get(0).getAdditionalInfo());
                ++trustedCertCounter;
            } else {
                ++untrustedCertCounter;
            }
        }
        assertEquals(subXCVs.size() - 1, untrustedCertCounter);
        assertEquals(1, trustedCertCounter);

        validateBestSigningTimes(reports);
        checkReports(reports);
    }

    // TODO : currently not supported case in the standard v1.4.1 (-LT signature with expired sig cert chain sunset date)
    @Test
    void oneTrustAnchorsFirstExpiredAndRevokedAfterBSTTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_sunset_multiple_trust_anchors.xml"));
        assertNotNull(xmlDiagnosticData);

        Calendar calendar = Calendar.getInstance();
        calendar.set(2023, Calendar.JANUARY, 1, 0, 0, 0);
        Date validationTime = calendar.getTime();

        xmlDiagnosticData.setValidationDate(validationTime);

        calendar.set(2022, Calendar.FEBRUARY, 1, 0, 0, 0);
        Date revocationTime = calendar.getTime();

        List<XmlChainItem> certificateChain = xmlDiagnosticData.getSignatures().get(0).getCertificateChain();
        XmlCertificate caCertificate = certificateChain.get(1).getCertificate();
        XmlCertificateRevocation xmlCertificateRevocation = caCertificate.getRevocations().get(0);
        xmlCertificateRevocation.setStatus(CertificateStatus.REVOKED);
        xmlCertificateRevocation.setReason(RevocationReason.CA_COMPROMISE);
        xmlCertificateRevocation.setRevocationDate(revocationTime);

        XmlCertificate rootCertificate = certificateChain.get(2).getCertificate();
        rootCertificate.getTrusted().setValue(false);
        rootCertificate.getSources().remove(CertificateSourceType.TRUSTED_STORE);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();
        assertNotNull(reports);

        DiagnosticData diagnosticData = reports.getDiagnosticData();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.NO_CERTIFICATE_CHAIN_FOUND_NO_POE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_XCV_HPCCVVT_ANS)));

        String firstTstId = simpleReport.getSignatureTimestamps(simpleReport.getFirstSignatureId()).get(0).getId();
        assertEquals(Indication.PASSED, simpleReport.getIndication(firstTstId));

        DetailedReport detailedReport = reports.getDetailedReport();
        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertNotNull(signatureBBB);
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.NO_CERTIFICATE_CHAIN_FOUND_NO_POE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(convert(signatureBBB.getConclusion().getErrors()), i18nProvider.getMessage(MessageTag.BBB_XCV_HPCCVVT_ANS)));

        XmlXCV xcv = signatureBBB.getXCV();
        assertNotNull(xcv);
        assertEquals(Indication.INDETERMINATE, xcv.getConclusion().getIndication());
        assertEquals(SubIndication.NO_CERTIFICATE_CHAIN_FOUND_NO_POE, xcv.getConclusion().getSubIndication());
        assertTrue(checkMessageValuePresence(convert(xcv.getConclusion().getErrors()), i18nProvider.getMessage(MessageTag.BBB_XCV_HPCCVVT_ANS)));

        int prospectiveChainFoundCounter = 0;
        int trustAnchorSunsetCheckValidCounter = 0;
        int trustAnchorSunsetCheckInvalidCounter = 0;
        int validProspectiveChainFoundCounter = 0;
        int invalidProspectiveChainFoundCounter = 0;
        int xmlSubXCVCheckValidCounter = 0;
        int xmlSubXCVCheckInvalidCounter = 0;

        for (XmlConstraint xmlConstraint : xcv.getConstraint()) {
            if (MessageTag.BBB_XCV_CCCBB.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                ++prospectiveChainFoundCounter;
            } else if (MessageTag.BBB_XCV_IVTBCTSD.getId().equals(xmlConstraint.getName().getKey())) {
                assertNotNull(xmlConstraint.getId());
                assertEquals(i18nProvider.getMessage(MessageTag.CERTIFICATE_SUNSET_DATE,
                                ValidationProcessUtils.getFormattedDate(xmlDiagnosticData.getValidationDate()),
                                ValidationProcessUtils.getFormattedDate(diagnosticData.getCertificateById(xmlConstraint.getId()).getTrustSunsetDate())),
                        xmlConstraint.getAdditionalInfo());
                if (XmlStatus.OK == xmlConstraint.getStatus()) {
                    ++trustAnchorSunsetCheckValidCounter;
                } else if (XmlStatus.WARNING == xmlConstraint.getStatus()) {
                    assertEquals(MessageTag.BBB_XCV_IVTBCTSD_ANS.getId(), xmlConstraint.getWarning().getKey());
                    ++trustAnchorSunsetCheckInvalidCounter;
                }
            } else if (MessageTag.BBB_XCV_HPCCVVT.getId().equals(xmlConstraint.getName().getKey())) {
                if (XmlStatus.OK == xmlConstraint.getStatus()) {
                    ++validProspectiveChainFoundCounter;
                } else if (XmlStatus.NOT_OK == xmlConstraint.getStatus()) {
                    assertEquals(MessageTag.BBB_XCV_HPCCVVT_ANS.getId(), xmlConstraint.getError().getKey());
                    ++ invalidProspectiveChainFoundCounter;
                }
            } else if (MessageTag.BBB_XCV_SUB.getId().equals(xmlConstraint.getName().getKey())) {
                assertNotNull(xmlConstraint.getId());
                if (XmlStatus.OK == xmlConstraint.getStatus()) {
                    ++xmlSubXCVCheckValidCounter;
                } else if (XmlStatus.NOT_OK == xmlConstraint.getStatus()) {
                    assertEquals(MessageTag.BBB_XCV_SUB_ANS.getId(), xmlConstraint.getError().getKey());
                    ++xmlSubXCVCheckInvalidCounter;
                }
            }
        }

        assertEquals(1, prospectiveChainFoundCounter);
        assertEquals(0, trustAnchorSunsetCheckValidCounter);
        assertEquals(1, trustAnchorSunsetCheckInvalidCounter);
        assertEquals(0, validProspectiveChainFoundCounter);
        assertEquals(1, invalidProspectiveChainFoundCounter);
        assertEquals(0, xmlSubXCVCheckValidCounter);
        assertEquals(0, xmlSubXCVCheckInvalidCounter);

        List<XmlSubXCV> subXCVs = xcv.getSubXCV();
        assertEquals(2, subXCVs.size());

        int untrustedCertCounter = 0;
        int trustedCertValidCounter = 0;
        int trustedCertInvalidCounter = 0;
        for (XmlSubXCV subXCV : subXCVs) {
            if (subXCV.isTrustAnchor()) {
                boolean sunsetCheckFound = false;
                boolean revocationCheckFound = false;
                for (XmlConstraint xmlConstraint : subXCV.getConstraint()) {
                    if (MessageTag.BBB_XCV_IVTBCTSD.getId().equals(xmlConstraint.getName().getKey())) {
                        if (XmlStatus.OK.equals(xmlConstraint.getStatus())) {
                            assertEquals(1, Utils.collectionSize(subXCV.getConstraint()));
                            ++trustedCertValidCounter;
                        } else if (XmlStatus.WARNING.equals(xmlConstraint.getStatus())) {
                            assertEquals(MessageTag.BBB_XCV_IVTBCTSD_ANS.getId(), xmlConstraint.getWarning().getKey());
                            assertEquals(i18nProvider.getMessage(MessageTag.CERTIFICATE_SUNSET_DATE,
                                            ValidationProcessUtils.getFormattedDate(xmlDiagnosticData.getValidationDate()),
                                            ValidationProcessUtils.getFormattedDate(diagnosticData.getCertificateById(subXCV.getId()).getTrustSunsetDate())),
                                    subXCV.getConstraint().get(0).getAdditionalInfo());
                            assertTrue(Utils.collectionSize(subXCV.getConstraint()) > 1);
                            ++trustedCertInvalidCounter;
                        }
                        sunsetCheckFound = true;
                    } else if (MessageTag.BBB_XCV_IOTAA.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                        assertEquals(MessageTag.BBB_XCV_IOTAA_ANS.getId(), xmlConstraint.getError().getKey());
                        revocationCheckFound = true;
                    } else {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                    }
                }
                assertEquals(Utils.collectionSize(subXCV.getConstraint()) > 1, revocationCheckFound);
                assertTrue(sunsetCheckFound);
            } else {
                ++untrustedCertCounter;
            }
        }
        assertEquals(1, untrustedCertCounter);
        assertEquals(0, trustedCertValidCounter);
        assertEquals(1, trustedCertInvalidCounter);

        XmlBasicBuildingBlocks timestampBBB = detailedReport.getBasicBuildingBlockById(firstTstId);

        xcv = timestampBBB.getXCV();
        assertNotNull(xcv);
        assertEquals(Indication.PASSED, xcv.getConclusion().getIndication());
        subXCVs = xcv.getSubXCV();

        untrustedCertCounter = 0;
        int trustedCertCounter = 0;
        for (XmlSubXCV subXCV : subXCVs) {
            if (subXCV.isTrustAnchor()) {
                assertEquals(1, subXCV.getConstraint().size());
                assertEquals(MessageTag.BBB_XCV_IVTBCTSD.getId(), subXCV.getConstraint().get(0).getName().getKey());
                assertEquals(XmlStatus.OK, subXCV.getConstraint().get(0).getStatus());
                assertEquals(i18nProvider.getMessage(MessageTag.CERTIFICATE_SUNSET_DATE,
                                ValidationProcessUtils.getFormattedDate(xmlDiagnosticData.getValidationDate()),
                                ValidationProcessUtils.getFormattedDate(diagnosticData.getCertificateById(subXCV.getId()).getTrustSunsetDate())),
                        subXCV.getConstraint().get(0).getAdditionalInfo());
                ++trustedCertCounter;
            } else {
                ++untrustedCertCounter;
            }
        }
        assertEquals(subXCVs.size() - 1, untrustedCertCounter);
        assertEquals(1, trustedCertCounter);

        validateBestSigningTimes(reports);
        checkReports(reports);
    }

    @Test
    void oneTrustAnchorsFirstExpireNoRevocationDataTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_sunset_multiple_trust_anchors.xml"));
        assertNotNull(xmlDiagnosticData);

        Calendar calendar = Calendar.getInstance();
        calendar.set(2023, Calendar.JANUARY, 1, 0, 0, 0);
        Date validationTime = calendar.getTime();

        xmlDiagnosticData.setValidationDate(validationTime);

        List<XmlChainItem> certificateChain = xmlDiagnosticData.getSignatures().get(0).getCertificateChain();
        XmlCertificate rootCertificate = certificateChain.get(2).getCertificate();
        rootCertificate.getTrusted().setValue(false);
        rootCertificate.getSources().remove(CertificateSourceType.TRUSTED_STORE);

        List<XmlCertificateExtension> certificateExtensions = xmlDiagnosticData.getSignatures().get(0)
                .getSigningCertificate().getCertificate().getCertificateExtensions();
        XmlValAssuredShortTermCertificate valAssuredShortTermCertificate = new XmlValAssuredShortTermCertificate();
        valAssuredShortTermCertificate.setOID(CertificateExtensionEnum.VALIDITY_ASSURED_SHORT_TERM.getOid());
        valAssuredShortTermCertificate.setPresent(true);
        certificateExtensions.add(valAssuredShortTermCertificate);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();
        assertNotNull(reports);

        DiagnosticData diagnosticData = reports.getDiagnosticData();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertFalse(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_XCV_HPCCVVT_ANS)));
        assertFalse(checkMessageValuePresence(simpleReport.getAdESValidationWarnings(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_XCV_HPCCVVT_ANS)));
        assertFalse(checkMessageValuePresence(simpleReport.getAdESValidationInfo(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_XCV_HPCCVVT_ANS)));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationInfo(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_XCV_IRDCSFC_ANS)));

        String firstTstId = simpleReport.getSignatureTimestamps(simpleReport.getFirstSignatureId()).get(0).getId();
        assertEquals(Indication.PASSED, simpleReport.getIndication(firstTstId));

        DetailedReport detailedReport = reports.getDetailedReport();
        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertNotNull(signatureBBB);
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(convert(signatureBBB.getConclusion().getErrors()), i18nProvider.getMessage(MessageTag.BBB_XCV_HPCCVVT_ANS)));
        assertTrue(checkMessageValuePresence(convert(signatureBBB.getConclusion().getInfos()), i18nProvider.getMessage(MessageTag.BBB_XCV_IRDCSFC_ANS)));

        XmlXCV xcv = signatureBBB.getXCV();
        assertNotNull(xcv);
        assertEquals(Indication.INDETERMINATE, xcv.getConclusion().getIndication());
        assertEquals(SubIndication.NO_CERTIFICATE_CHAIN_FOUND_NO_POE, xcv.getConclusion().getSubIndication());
        assertTrue(checkMessageValuePresence(convert(xcv.getConclusion().getErrors()), i18nProvider.getMessage(MessageTag.BBB_XCV_HPCCVVT_ANS)));

        int prospectiveChainFoundCounter = 0;
        int trustAnchorSunsetCheckValidCounter = 0;
        int trustAnchorSunsetCheckInvalidCounter = 0;
        int validProspectiveChainFoundCounter = 0;
        int invalidProspectiveChainFoundCounter = 0;
        int xmlSubXCVCheckValidCounter = 0;
        int xmlSubXCVCheckInvalidCounter = 0;

        for (XmlConstraint xmlConstraint : xcv.getConstraint()) {
            if (MessageTag.BBB_XCV_CCCBB.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                ++prospectiveChainFoundCounter;
            } else if (MessageTag.BBB_XCV_IVTBCTSD.getId().equals(xmlConstraint.getName().getKey())) {
                assertNotNull(xmlConstraint.getId());
                assertEquals(i18nProvider.getMessage(MessageTag.CERTIFICATE_SUNSET_DATE,
                                ValidationProcessUtils.getFormattedDate(xmlDiagnosticData.getValidationDate()),
                                ValidationProcessUtils.getFormattedDate(diagnosticData.getCertificateById(xmlConstraint.getId()).getTrustSunsetDate())),
                        xmlConstraint.getAdditionalInfo());
                if (XmlStatus.OK == xmlConstraint.getStatus()) {
                    ++trustAnchorSunsetCheckValidCounter;
                } else if (XmlStatus.WARNING == xmlConstraint.getStatus()) {
                    assertEquals(MessageTag.BBB_XCV_IVTBCTSD_ANS.getId(), xmlConstraint.getWarning().getKey());
                    ++trustAnchorSunsetCheckInvalidCounter;
                }
            } else if (MessageTag.BBB_XCV_HPCCVVT.getId().equals(xmlConstraint.getName().getKey())) {
                if (XmlStatus.OK == xmlConstraint.getStatus()) {
                    ++validProspectiveChainFoundCounter;
                } else if (XmlStatus.NOT_OK == xmlConstraint.getStatus()) {
                    assertEquals(MessageTag.BBB_XCV_HPCCVVT_ANS.getId(), xmlConstraint.getError().getKey());
                    ++ invalidProspectiveChainFoundCounter;
                }
            } else if (MessageTag.BBB_XCV_SUB.getId().equals(xmlConstraint.getName().getKey())) {
                assertNotNull(xmlConstraint.getId());
                if (XmlStatus.OK == xmlConstraint.getStatus()) {
                    ++xmlSubXCVCheckValidCounter;
                } else if (XmlStatus.NOT_OK == xmlConstraint.getStatus()) {
                    assertEquals(MessageTag.BBB_XCV_SUB_ANS.getId(), xmlConstraint.getError().getKey());
                    ++xmlSubXCVCheckInvalidCounter;
                }
            }
        }

        assertEquals(1, prospectiveChainFoundCounter);
        assertEquals(0, trustAnchorSunsetCheckValidCounter);
        assertEquals(1, trustAnchorSunsetCheckInvalidCounter);
        assertEquals(0, validProspectiveChainFoundCounter);
        assertEquals(1, invalidProspectiveChainFoundCounter);
        assertEquals(0, xmlSubXCVCheckValidCounter);
        assertEquals(0, xmlSubXCVCheckInvalidCounter);

        List<XmlSubXCV> subXCVs = xcv.getSubXCV();
        assertEquals(2, subXCVs.size());

        int untrustedCertCounter = 0;
        int trustedCertValidCounter = 0;
        int trustedCertInvalidCounter = 0;
        for (XmlSubXCV subXCV : subXCVs) {
            if (subXCV.isTrustAnchor()) {
                boolean sunsetCheckFound = false;
                boolean revocationCheckFound = false;
                for (XmlConstraint xmlConstraint : subXCV.getConstraint()) {
                    if (MessageTag.BBB_XCV_IVTBCTSD.getId().equals(xmlConstraint.getName().getKey())) {
                        if (XmlStatus.OK.equals(xmlConstraint.getStatus())) {
                            assertEquals(1, Utils.collectionSize(subXCV.getConstraint()));
                            ++trustedCertValidCounter;
                        } else if (XmlStatus.WARNING.equals(xmlConstraint.getStatus())) {
                            assertEquals(MessageTag.BBB_XCV_IVTBCTSD_ANS.getId(), xmlConstraint.getWarning().getKey());
                            assertEquals(i18nProvider.getMessage(MessageTag.CERTIFICATE_SUNSET_DATE,
                                            ValidationProcessUtils.getFormattedDate(xmlDiagnosticData.getValidationDate()),
                                            ValidationProcessUtils.getFormattedDate(diagnosticData.getCertificateById(subXCV.getId()).getTrustSunsetDate())),
                                    subXCV.getConstraint().get(0).getAdditionalInfo());
                            assertTrue(Utils.collectionSize(subXCV.getConstraint()) > 1);
                            ++trustedCertInvalidCounter;
                        }
                        sunsetCheckFound = true;
                    } else if (MessageTag.BBB_XCV_IOTAA.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                        assertEquals(MessageTag.BBB_XCV_IOTAA_ANS.getId(), xmlConstraint.getError().getKey());
                        revocationCheckFound = true;
                    } else {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                    }
                }
                assertEquals(Utils.collectionSize(subXCV.getConstraint()) > 1, revocationCheckFound);
                assertTrue(sunsetCheckFound);
            } else {
                ++untrustedCertCounter;
            }
        }
        assertEquals(1, untrustedCertCounter);
        assertEquals(0, trustedCertValidCounter);
        assertEquals(1, trustedCertInvalidCounter);

        XmlPSV psv = signatureBBB.getPSV();
        assertNotNull(psv);
        assertEquals(Indication.PASSED, psv.getConclusion().getIndication());
        assertFalse(checkMessageValuePresence(convert(psv.getConclusion().getErrors()), i18nProvider.getMessage(MessageTag.BBB_XCV_HPCCVVT_ANS)));
        assertFalse(checkMessageValuePresence(convert(psv.getConclusion().getWarnings()), i18nProvider.getMessage(MessageTag.BBB_XCV_HPCCVVT_ANS)));
        assertFalse(checkMessageValuePresence(convert(psv.getConclusion().getInfos()), i18nProvider.getMessage(MessageTag.BBB_XCV_HPCCVVT_ANS)));

        XmlPCV pcv = signatureBBB.getPCV();
        assertNotNull(pcv);
        assertEquals(Indication.PASSED, pcv.getConclusion().getIndication());
        assertFalse(checkMessageValuePresence(convert(pcv.getConclusion().getErrors()), i18nProvider.getMessage(MessageTag.BBB_XCV_HPCCVVT_ANS)));
        assertFalse(checkMessageValuePresence(convert(pcv.getConclusion().getWarnings()), i18nProvider.getMessage(MessageTag.BBB_XCV_HPCCVVT_ANS)));
        assertFalse(checkMessageValuePresence(convert(pcv.getConclusion().getInfos()), i18nProvider.getMessage(MessageTag.BBB_XCV_HPCCVVT_ANS)));

        XmlVTS vts = signatureBBB.getVTS();
        assertNotNull(vts);
        assertEquals(Indication.PASSED, vts.getConclusion().getIndication());
        assertFalse(checkMessageValuePresence(convert(vts.getConclusion().getErrors()), i18nProvider.getMessage(MessageTag.BBB_XCV_HPCCVVT_ANS)));
        assertFalse(checkMessageValuePresence(convert(vts.getConclusion().getWarnings()), i18nProvider.getMessage(MessageTag.BBB_XCV_HPCCVVT_ANS)));
        assertFalse(checkMessageValuePresence(convert(vts.getConclusion().getInfos()), i18nProvider.getMessage(MessageTag.BBB_XCV_HPCCVVT_ANS)));
        assertTrue(checkMessageValuePresence(convert(vts.getConclusion().getInfos()), i18nProvider.getMessage(MessageTag.BBB_XCV_IRDCSFC_ANS)));

        XmlBasicBuildingBlocks timestampBBB = detailedReport.getBasicBuildingBlockById(firstTstId);

        xcv = timestampBBB.getXCV();
        assertNotNull(xcv);
        assertEquals(Indication.PASSED, xcv.getConclusion().getIndication());
        subXCVs = xcv.getSubXCV();

        untrustedCertCounter = 0;
        int trustedCertCounter = 0;
        for (XmlSubXCV subXCV : subXCVs) {
            if (subXCV.isTrustAnchor()) {
                assertEquals(1, subXCV.getConstraint().size());
                assertEquals(MessageTag.BBB_XCV_IVTBCTSD.getId(), subXCV.getConstraint().get(0).getName().getKey());
                assertEquals(XmlStatus.OK, subXCV.getConstraint().get(0).getStatus());
                assertEquals(i18nProvider.getMessage(MessageTag.CERTIFICATE_SUNSET_DATE,
                                ValidationProcessUtils.getFormattedDate(xmlDiagnosticData.getValidationDate()),
                                ValidationProcessUtils.getFormattedDate(diagnosticData.getCertificateById(subXCV.getId()).getTrustSunsetDate())),
                        subXCV.getConstraint().get(0).getAdditionalInfo());
                ++trustedCertCounter;
            } else {
                ++untrustedCertCounter;
            }
        }
        assertEquals(subXCVs.size() - 1, untrustedCertCounter);
        assertEquals(1, trustedCertCounter);

        validateBestSigningTimes(reports);
        checkReports(reports);
    }

    @Test
    void signCertTrustedTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_trusted_sign_cert_sunset.xml"));
        assertNotNull(xmlDiagnosticData);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();
        assertNotNull(reports);

        DiagnosticData diagnosticData = reports.getDiagnosticData();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId())));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationWarnings(simpleReport.getFirstSignatureId())));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationInfo(simpleReport.getFirstSignatureId())));

        DetailedReport detailedReport = reports.getDetailedReport();
        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertNotNull(signatureBBB);
        assertEquals(Indication.PASSED, signatureBBB.getConclusion().getIndication());

        XmlXCV xcv = signatureBBB.getXCV();
        assertNotNull(xcv);
        assertEquals(Indication.PASSED, xcv.getConclusion().getIndication());
        assertTrue(Utils.isCollectionEmpty(xcv.getConclusion().getErrors()));
        assertTrue(Utils.isCollectionEmpty(xcv.getConclusion().getWarnings()));
        assertTrue(Utils.isCollectionEmpty(xcv.getConclusion().getInfos()));

        int prospectiveChainFoundCounter = 0;
        int trustAnchorSunsetCheckValidCounter = 0;
        int trustAnchorSunsetCheckInvalidCounter = 0;
        int validProspectiveChainFoundCounter = 0;
        int invalidProspectiveChainFoundCounter = 0;
        int xmlSubXCVCheckValidCounter = 0;
        int xmlSubXCVCheckInvalidCounter = 0;

        for (XmlConstraint xmlConstraint : xcv.getConstraint()) {
            if (MessageTag.BBB_XCV_CCCBB.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                ++prospectiveChainFoundCounter;
            } else if (MessageTag.BBB_XCV_IVTBCTSD.getId().equals(xmlConstraint.getName().getKey())) {
                assertNotNull(xmlConstraint.getId());
                assertEquals(i18nProvider.getMessage(MessageTag.CERTIFICATE_SUNSET_DATE,
                                ValidationProcessUtils.getFormattedDate(xmlDiagnosticData.getValidationDate()),
                                ValidationProcessUtils.getFormattedDate(diagnosticData.getCertificateById(xmlConstraint.getId()).getTrustSunsetDate())),
                        xmlConstraint.getAdditionalInfo());
                if (XmlStatus.OK == xmlConstraint.getStatus()) {
                    ++trustAnchorSunsetCheckValidCounter;
                } else if (XmlStatus.WARNING == xmlConstraint.getStatus()) {
                    assertEquals(MessageTag.BBB_XCV_IVTBCTSD_ANS.getId(), xmlConstraint.getWarning().getKey());
                    ++trustAnchorSunsetCheckInvalidCounter;
                }
            } else if (MessageTag.BBB_XCV_HPCCVVT.getId().equals(xmlConstraint.getName().getKey())) {
                if (XmlStatus.OK == xmlConstraint.getStatus()) {
                    ++validProspectiveChainFoundCounter;
                } else if (XmlStatus.NOT_OK == xmlConstraint.getStatus()) {
                    assertEquals(MessageTag.BBB_XCV_HPCCVVT_ANS.getId(), xmlConstraint.getError().getKey());
                    ++ invalidProspectiveChainFoundCounter;
                }
            } else if (MessageTag.BBB_XCV_SUB.getId().equals(xmlConstraint.getName().getKey())) {
                assertNotNull(xmlConstraint.getId());
                if (XmlStatus.OK == xmlConstraint.getStatus()) {
                    ++xmlSubXCVCheckValidCounter;
                } else if (XmlStatus.NOT_OK == xmlConstraint.getStatus()) {
                    assertEquals(MessageTag.BBB_XCV_SUB_ANS.getId(), xmlConstraint.getError().getKey());
                    ++xmlSubXCVCheckInvalidCounter;
                }
            }
        }

        assertEquals(1, prospectiveChainFoundCounter);
        assertEquals(1, trustAnchorSunsetCheckValidCounter);
        assertEquals(0, trustAnchorSunsetCheckInvalidCounter);
        assertEquals(1, validProspectiveChainFoundCounter);
        assertEquals(0, invalidProspectiveChainFoundCounter);
        assertEquals(1, xmlSubXCVCheckValidCounter);
        assertEquals(0, xmlSubXCVCheckInvalidCounter);

        List<XmlSubXCV> subXCVs = xcv.getSubXCV();
        assertEquals(1, subXCVs.size());

        int untrustedCertCounter = 0;
        int trustedCertCounter = 0;
        for (XmlSubXCV subXCV : subXCVs) {
            if (subXCV.isTrustAnchor()) {
                assertEquals(1, subXCV.getConstraint().size());
                assertEquals(MessageTag.BBB_XCV_IVTBCTSD.getId(), subXCV.getConstraint().get(0).getName().getKey());
                assertEquals(XmlStatus.OK, subXCV.getConstraint().get(0).getStatus());
                assertEquals(i18nProvider.getMessage(MessageTag.CERTIFICATE_SUNSET_DATE,
                                ValidationProcessUtils.getFormattedDate(xmlDiagnosticData.getValidationDate()),
                                ValidationProcessUtils.getFormattedDate(diagnosticData.getCertificateById(subXCV.getId()).getTrustSunsetDate())),
                        subXCV.getConstraint().get(0).getAdditionalInfo());
                ++trustedCertCounter;
            } else {
                ++untrustedCertCounter;
            }
        }
        assertEquals(0, untrustedCertCounter);
        assertEquals(1, trustedCertCounter);

        validateBestSigningTimes(reports);
        checkReports(reports);
    }

    @Test
    void signCertTrustedCertExpiredTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_trusted_sign_cert_sunset.xml"));
        assertNotNull(xmlDiagnosticData);

        Calendar calendar = Calendar.getInstance();
        calendar.set(2022, Calendar.JANUARY, 0, 0, 0, 0);
        Date validationTime = calendar.getTime();

        xmlDiagnosticData.setValidationDate(validationTime);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();
        assertNotNull(reports);

        DiagnosticData diagnosticData = reports.getDiagnosticData();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId())));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationWarnings(simpleReport.getFirstSignatureId())));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationInfo(simpleReport.getFirstSignatureId())));

        DetailedReport detailedReport = reports.getDetailedReport();
        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertNotNull(signatureBBB);
        assertEquals(Indication.PASSED, signatureBBB.getConclusion().getIndication());

        XmlXCV xcv = signatureBBB.getXCV();
        assertNotNull(xcv);
        assertEquals(Indication.PASSED, xcv.getConclusion().getIndication());
        assertTrue(Utils.isCollectionEmpty(xcv.getConclusion().getErrors()));
        assertTrue(Utils.isCollectionEmpty(xcv.getConclusion().getWarnings()));
        assertTrue(Utils.isCollectionEmpty(xcv.getConclusion().getInfos()));

        int prospectiveChainFoundCounter = 0;
        int trustAnchorSunsetCheckValidCounter = 0;
        int trustAnchorSunsetCheckInvalidCounter = 0;
        int validProspectiveChainFoundCounter = 0;
        int invalidProspectiveChainFoundCounter = 0;
        int xmlSubXCVCheckValidCounter = 0;
        int xmlSubXCVCheckInvalidCounter = 0;

        for (XmlConstraint xmlConstraint : xcv.getConstraint()) {
            if (MessageTag.BBB_XCV_CCCBB.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                ++prospectiveChainFoundCounter;
            } else if (MessageTag.BBB_XCV_IVTBCTSD.getId().equals(xmlConstraint.getName().getKey())) {
                assertNotNull(xmlConstraint.getId());
                assertEquals(i18nProvider.getMessage(MessageTag.CERTIFICATE_SUNSET_DATE,
                                ValidationProcessUtils.getFormattedDate(xmlDiagnosticData.getValidationDate()),
                                ValidationProcessUtils.getFormattedDate(diagnosticData.getCertificateById(xmlConstraint.getId()).getTrustSunsetDate())),
                        xmlConstraint.getAdditionalInfo());
                if (XmlStatus.OK == xmlConstraint.getStatus()) {
                    ++trustAnchorSunsetCheckValidCounter;
                } else if (XmlStatus.WARNING == xmlConstraint.getStatus()) {
                    assertEquals(MessageTag.BBB_XCV_IVTBCTSD_ANS.getId(), xmlConstraint.getWarning().getKey());
                    ++trustAnchorSunsetCheckInvalidCounter;
                }
            } else if (MessageTag.BBB_XCV_HPCCVVT.getId().equals(xmlConstraint.getName().getKey())) {
                if (XmlStatus.OK == xmlConstraint.getStatus()) {
                    ++validProspectiveChainFoundCounter;
                } else if (XmlStatus.NOT_OK == xmlConstraint.getStatus()) {
                    assertEquals(MessageTag.BBB_XCV_HPCCVVT_ANS.getId(), xmlConstraint.getError().getKey());
                    ++ invalidProspectiveChainFoundCounter;
                }
            } else if (MessageTag.BBB_XCV_SUB.getId().equals(xmlConstraint.getName().getKey())) {
                assertNotNull(xmlConstraint.getId());
                if (XmlStatus.OK == xmlConstraint.getStatus()) {
                    ++xmlSubXCVCheckValidCounter;
                } else if (XmlStatus.NOT_OK == xmlConstraint.getStatus()) {
                    assertEquals(MessageTag.BBB_XCV_SUB_ANS.getId(), xmlConstraint.getError().getKey());
                    ++xmlSubXCVCheckInvalidCounter;
                }
            }
        }

        assertEquals(1, prospectiveChainFoundCounter);
        assertEquals(1, trustAnchorSunsetCheckValidCounter);
        assertEquals(0, trustAnchorSunsetCheckInvalidCounter);
        assertEquals(1, validProspectiveChainFoundCounter);
        assertEquals(0, invalidProspectiveChainFoundCounter);
        assertEquals(1, xmlSubXCVCheckValidCounter);
        assertEquals(0, xmlSubXCVCheckInvalidCounter);

        List<XmlSubXCV> subXCVs = xcv.getSubXCV();
        assertEquals(1, subXCVs.size());

        int untrustedCertCounter = 0;
        int trustedCertCounter = 0;
        for (XmlSubXCV subXCV : subXCVs) {
            if (subXCV.isTrustAnchor()) {
                assertEquals(1, subXCV.getConstraint().size());
                assertEquals(MessageTag.BBB_XCV_IVTBCTSD.getId(), subXCV.getConstraint().get(0).getName().getKey());
                assertEquals(XmlStatus.OK, subXCV.getConstraint().get(0).getStatus());
                assertEquals(i18nProvider.getMessage(MessageTag.CERTIFICATE_SUNSET_DATE,
                                ValidationProcessUtils.getFormattedDate(xmlDiagnosticData.getValidationDate()),
                                ValidationProcessUtils.getFormattedDate(diagnosticData.getCertificateById(subXCV.getId()).getTrustSunsetDate())),
                        subXCV.getConstraint().get(0).getAdditionalInfo());
                ++trustedCertCounter;
            } else {
                ++untrustedCertCounter;
            }
        }
        assertEquals(0, untrustedCertCounter);
        assertEquals(1, trustedCertCounter);

        validateBestSigningTimes(reports);
        checkReports(reports);
    }

    @Test
    void signCertTrustedSunsetExpiredTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_trusted_sign_cert_sunset.xml"));
        assertNotNull(xmlDiagnosticData);

        Calendar calendar = Calendar.getInstance();
        calendar.set(2023, Calendar.JANUARY, 0, 0, 0, 0);
        Date validationTime = calendar.getTime();

        xmlDiagnosticData.setValidationDate(validationTime);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();
        assertNotNull(reports);

        DiagnosticData diagnosticData = reports.getDiagnosticData();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.NO_CERTIFICATE_CHAIN_FOUND_NO_POE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_XCV_HPCCVVT_ANS)));

        DetailedReport detailedReport = reports.getDetailedReport();
        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertNotNull(signatureBBB);
        assertEquals(Indication.INDETERMINATE, signatureBBB.getConclusion().getIndication());
        assertEquals(SubIndication.NO_CERTIFICATE_CHAIN_FOUND_NO_POE, signatureBBB.getConclusion().getSubIndication());
        assertTrue(checkMessageValuePresence(convert(signatureBBB.getConclusion().getErrors()),
                i18nProvider.getMessage(MessageTag.BBB_XCV_HPCCVVT_ANS)));

        XmlXCV xcv = signatureBBB.getXCV();
        assertNotNull(xcv);
        assertEquals(Indication.INDETERMINATE, xcv.getConclusion().getIndication());
        assertEquals(SubIndication.NO_CERTIFICATE_CHAIN_FOUND_NO_POE, xcv.getConclusion().getSubIndication());
        assertTrue(checkMessageValuePresence(convert(xcv.getConclusion().getErrors()),
                i18nProvider.getMessage(MessageTag.BBB_XCV_HPCCVVT_ANS)));

        int prospectiveChainFoundCounter = 0;
        int trustAnchorSunsetCheckValidCounter = 0;
        int trustAnchorSunsetCheckInvalidCounter = 0;
        int validProspectiveChainFoundCounter = 0;
        int invalidProspectiveChainFoundCounter = 0;
        int xmlSubXCVCheckValidCounter = 0;
        int xmlSubXCVCheckInvalidCounter = 0;

        for (XmlConstraint xmlConstraint : xcv.getConstraint()) {
            if (MessageTag.BBB_XCV_CCCBB.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                ++prospectiveChainFoundCounter;
            } else if (MessageTag.BBB_XCV_IVTBCTSD.getId().equals(xmlConstraint.getName().getKey())) {
                assertNotNull(xmlConstraint.getId());
                assertEquals(i18nProvider.getMessage(MessageTag.CERTIFICATE_SUNSET_DATE,
                                ValidationProcessUtils.getFormattedDate(xmlDiagnosticData.getValidationDate()),
                                ValidationProcessUtils.getFormattedDate(diagnosticData.getCertificateById(xmlConstraint.getId()).getTrustSunsetDate())),
                        xmlConstraint.getAdditionalInfo());
                if (XmlStatus.OK == xmlConstraint.getStatus()) {
                    ++trustAnchorSunsetCheckValidCounter;
                } else if (XmlStatus.WARNING == xmlConstraint.getStatus()) {
                    assertEquals(MessageTag.BBB_XCV_IVTBCTSD_ANS.getId(), xmlConstraint.getWarning().getKey());
                    ++trustAnchorSunsetCheckInvalidCounter;
                }
            } else if (MessageTag.BBB_XCV_HPCCVVT.getId().equals(xmlConstraint.getName().getKey())) {
                if (XmlStatus.OK == xmlConstraint.getStatus()) {
                    ++validProspectiveChainFoundCounter;
                } else if (XmlStatus.NOT_OK == xmlConstraint.getStatus()) {
                    assertEquals(MessageTag.BBB_XCV_HPCCVVT_ANS.getId(), xmlConstraint.getError().getKey());
                    ++ invalidProspectiveChainFoundCounter;
                }
            } else if (MessageTag.BBB_XCV_SUB.getId().equals(xmlConstraint.getName().getKey())) {
                assertNotNull(xmlConstraint.getId());
                if (XmlStatus.OK == xmlConstraint.getStatus()) {
                    ++xmlSubXCVCheckValidCounter;
                } else if (XmlStatus.NOT_OK == xmlConstraint.getStatus()) {
                    assertEquals(MessageTag.BBB_XCV_SUB_ANS.getId(), xmlConstraint.getError().getKey());
                    ++xmlSubXCVCheckInvalidCounter;
                }
            }
        }

        assertEquals(1, prospectiveChainFoundCounter);
        assertEquals(0, trustAnchorSunsetCheckValidCounter);
        assertEquals(1, trustAnchorSunsetCheckInvalidCounter);
        assertEquals(0, validProspectiveChainFoundCounter);
        assertEquals(1, invalidProspectiveChainFoundCounter);
        assertEquals(0, xmlSubXCVCheckValidCounter);
        assertEquals(0, xmlSubXCVCheckInvalidCounter);

        List<XmlSubXCV> subXCVs = xcv.getSubXCV();
        assertEquals(1, subXCVs.size());

        int untrustedCertCounter = 0;
        int trustedCertCounter = 0;
        for (XmlSubXCV subXCV : subXCVs) {
            if (subXCV.isTrustAnchor()) {
                boolean validationTimeCheckFound = false;
                boolean validProspectiveChainCheckFound = false;
                for (XmlConstraint xmlConstraint : subXCV.getConstraint()) {
                    if (MessageTag.BBB_XCV_IVTBCTSD.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.WARNING, xmlConstraint.getStatus());
                        assertEquals(MessageTag.BBB_XCV_IVTBCTSD_ANS.getId(), xmlConstraint.getWarning().getKey());
                        assertEquals(i18nProvider.getMessage(MessageTag.CERTIFICATE_SUNSET_DATE,
                                ValidationProcessUtils.getFormattedDate(xmlDiagnosticData.getValidationDate()),
                                ValidationProcessUtils.getFormattedDate(diagnosticData.getCertificateById(subXCV.getId()).getTrustSunsetDate())), xmlConstraint.getAdditionalInfo());
                        validationTimeCheckFound = true;
                    } else if (MessageTag.BBB_XCV_IOTAA.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                        assertEquals(MessageTag.BBB_XCV_IOTAA_ANS.getId(), xmlConstraint.getError().getKey());
                        validProspectiveChainCheckFound = true;
                    }
                }
                assertTrue(validationTimeCheckFound);
                assertTrue(validProspectiveChainCheckFound);
                ++trustedCertCounter;
            } else {
                ++untrustedCertCounter;
            }
        }
        assertEquals(0, untrustedCertCounter);
        assertEquals(1, trustedCertCounter);

        validateBestSigningTimes(reports);
        checkReports(reports);
    }

    @Test
    void signCertTrustedSunsetExpiredSignCertWarnLevelTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_trusted_sign_cert_sunset.xml"));
        assertNotNull(xmlDiagnosticData);

        Calendar calendar = Calendar.getInstance();
        calendar.set(2023, Calendar.JANUARY, 0, 0, 0, 0);
        Date validationTime = calendar.getTime();

        xmlDiagnosticData.setValidationDate(validationTime);

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.WARN);
        validationPolicy.getSignatureConstraints().getBasicSignatureConstraints().getSigningCertificate().setSunsetDate(constraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();
        assertNotNull(reports);

        DiagnosticData diagnosticData = reports.getDiagnosticData();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationWarnings(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_XCV_HPCCVVT_ANS)));

        DetailedReport detailedReport = reports.getDetailedReport();
        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertNotNull(signatureBBB);
        assertEquals(Indication.PASSED, signatureBBB.getConclusion().getIndication());
        assertTrue(checkMessageValuePresence(convert(signatureBBB.getConclusion().getWarnings()),
                i18nProvider.getMessage(MessageTag.BBB_XCV_HPCCVVT_ANS)));

        XmlXCV xcv = signatureBBB.getXCV();
        assertNotNull(xcv);
        assertEquals(Indication.PASSED, xcv.getConclusion().getIndication());
        assertTrue(checkMessageValuePresence(convert(xcv.getConclusion().getWarnings()),
                i18nProvider.getMessage(MessageTag.BBB_XCV_HPCCVVT_ANS)));

        int prospectiveChainFoundCounter = 0;
        int trustAnchorSunsetCheckValidCounter = 0;
        int trustAnchorSunsetCheckInvalidCounter = 0;
        int validProspectiveChainFoundCounter = 0;
        int invalidProspectiveChainFoundCounter = 0;
        int xmlSubXCVCheckValidCounter = 0;
        int xmlSubXCVCheckInvalidCounter = 0;

        for (XmlConstraint xmlConstraint : xcv.getConstraint()) {
            if (MessageTag.BBB_XCV_CCCBB.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                ++prospectiveChainFoundCounter;
            } else if (MessageTag.BBB_XCV_IVTBCTSD.getId().equals(xmlConstraint.getName().getKey())) {
                assertNotNull(xmlConstraint.getId());
                assertEquals(i18nProvider.getMessage(MessageTag.CERTIFICATE_SUNSET_DATE,
                                ValidationProcessUtils.getFormattedDate(xmlDiagnosticData.getValidationDate()),
                                ValidationProcessUtils.getFormattedDate(diagnosticData.getCertificateById(xmlConstraint.getId()).getTrustSunsetDate())),
                        xmlConstraint.getAdditionalInfo());
                if (XmlStatus.OK == xmlConstraint.getStatus()) {
                    ++trustAnchorSunsetCheckValidCounter;
                } else if (XmlStatus.WARNING == xmlConstraint.getStatus()) {
                    assertEquals(MessageTag.BBB_XCV_IVTBCTSD_ANS.getId(), xmlConstraint.getWarning().getKey());
                    ++trustAnchorSunsetCheckInvalidCounter;
                }
            } else if (MessageTag.BBB_XCV_HPCCVVT.getId().equals(xmlConstraint.getName().getKey())) {
                if (XmlStatus.OK == xmlConstraint.getStatus()) {
                    ++validProspectiveChainFoundCounter;
                } else if (XmlStatus.WARNING == xmlConstraint.getStatus()) {
                    assertEquals(MessageTag.BBB_XCV_HPCCVVT_ANS.getId(), xmlConstraint.getWarning().getKey());
                    ++ invalidProspectiveChainFoundCounter;
                }
            } else if (MessageTag.BBB_XCV_SUB.getId().equals(xmlConstraint.getName().getKey())) {
                assertNotNull(xmlConstraint.getId());
                if (XmlStatus.OK == xmlConstraint.getStatus()) {
                    ++xmlSubXCVCheckValidCounter;
                } else if (XmlStatus.NOT_OK == xmlConstraint.getStatus()) {
                    assertEquals(MessageTag.BBB_XCV_SUB_ANS.getId(), xmlConstraint.getError().getKey());
                    ++xmlSubXCVCheckInvalidCounter;
                }
            }
        }

        assertEquals(1, prospectiveChainFoundCounter);
        assertEquals(0, trustAnchorSunsetCheckValidCounter);
        assertEquals(1, trustAnchorSunsetCheckInvalidCounter);
        assertEquals(0, validProspectiveChainFoundCounter);
        assertEquals(1, invalidProspectiveChainFoundCounter);
        assertEquals(1, xmlSubXCVCheckValidCounter);
        assertEquals(0, xmlSubXCVCheckInvalidCounter);

        List<XmlSubXCV> subXCVs = xcv.getSubXCV();
        assertEquals(1, subXCVs.size());

        int untrustedCertCounter = 0;
        int trustedCertCounter = 0;
        for (XmlSubXCV subXCV : subXCVs) {
            if (subXCV.isTrustAnchor()) {
                boolean validationTimeCheckFound = false;
                boolean validProspectiveChainCheckFound = false;
                for (XmlConstraint xmlConstraint : subXCV.getConstraint()) {
                    if (MessageTag.BBB_XCV_IVTBCTSD.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.WARNING, xmlConstraint.getStatus());
                        assertEquals(MessageTag.BBB_XCV_IVTBCTSD_ANS.getId(), xmlConstraint.getWarning().getKey());
                        assertEquals(i18nProvider.getMessage(MessageTag.CERTIFICATE_SUNSET_DATE,
                                ValidationProcessUtils.getFormattedDate(xmlDiagnosticData.getValidationDate()),
                                ValidationProcessUtils.getFormattedDate(diagnosticData.getCertificateById(subXCV.getId()).getTrustSunsetDate())), xmlConstraint.getAdditionalInfo());
                        validationTimeCheckFound = true;
                    } else if (MessageTag.BBB_XCV_IOTAA.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.WARNING, xmlConstraint.getStatus());
                        assertEquals(MessageTag.BBB_XCV_IOTAA_ANS.getId(), xmlConstraint.getWarning().getKey());
                        validProspectiveChainCheckFound = true;
                    }
                }
                assertTrue(validationTimeCheckFound);
                assertTrue(validProspectiveChainCheckFound);
                ++trustedCertCounter;
            } else {
                ++untrustedCertCounter;
            }
        }
        assertEquals(0, untrustedCertCounter);
        assertEquals(1, trustedCertCounter);

        validateBestSigningTimes(reports);
        checkReports(reports);
    }

    @Test
    void signCertTrustedSunsetExpiredCAWarnLevelTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_trusted_sign_cert_sunset.xml"));
        assertNotNull(xmlDiagnosticData);

        Calendar calendar = Calendar.getInstance();
        calendar.set(2023, Calendar.JANUARY, 0, 0, 0, 0);
        Date validationTime = calendar.getTime();

        xmlDiagnosticData.setValidationDate(validationTime);

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.WARN);
        validationPolicy.getSignatureConstraints().getBasicSignatureConstraints().getCACertificate().setSunsetDate(constraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();
        assertNotNull(reports);

        DiagnosticData diagnosticData = reports.getDiagnosticData();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.NO_CERTIFICATE_CHAIN_FOUND_NO_POE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_XCV_HPCCVVT_ANS)));

        DetailedReport detailedReport = reports.getDetailedReport();
        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertNotNull(signatureBBB);
        assertEquals(Indication.INDETERMINATE, signatureBBB.getConclusion().getIndication());
        assertEquals(SubIndication.NO_CERTIFICATE_CHAIN_FOUND_NO_POE, signatureBBB.getConclusion().getSubIndication());
        assertTrue(checkMessageValuePresence(convert(signatureBBB.getConclusion().getErrors()),
                i18nProvider.getMessage(MessageTag.BBB_XCV_HPCCVVT_ANS)));

        XmlXCV xcv = signatureBBB.getXCV();
        assertNotNull(xcv);
        assertEquals(Indication.INDETERMINATE, xcv.getConclusion().getIndication());
        assertEquals(SubIndication.NO_CERTIFICATE_CHAIN_FOUND_NO_POE, xcv.getConclusion().getSubIndication());
        assertTrue(checkMessageValuePresence(convert(xcv.getConclusion().getErrors()),
                i18nProvider.getMessage(MessageTag.BBB_XCV_HPCCVVT_ANS)));

        int prospectiveChainFoundCounter = 0;
        int trustAnchorSunsetCheckValidCounter = 0;
        int trustAnchorSunsetCheckInvalidCounter = 0;
        int validProspectiveChainFoundCounter = 0;
        int invalidProspectiveChainFoundCounter = 0;
        int xmlSubXCVCheckValidCounter = 0;
        int xmlSubXCVCheckInvalidCounter = 0;

        for (XmlConstraint xmlConstraint : xcv.getConstraint()) {
            if (MessageTag.BBB_XCV_CCCBB.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                ++prospectiveChainFoundCounter;
            } else if (MessageTag.BBB_XCV_IVTBCTSD.getId().equals(xmlConstraint.getName().getKey())) {
                assertNotNull(xmlConstraint.getId());
                assertEquals(i18nProvider.getMessage(MessageTag.CERTIFICATE_SUNSET_DATE,
                                ValidationProcessUtils.getFormattedDate(xmlDiagnosticData.getValidationDate()),
                                ValidationProcessUtils.getFormattedDate(diagnosticData.getCertificateById(xmlConstraint.getId()).getTrustSunsetDate())),
                        xmlConstraint.getAdditionalInfo());
                if (XmlStatus.OK == xmlConstraint.getStatus()) {
                    ++trustAnchorSunsetCheckValidCounter;
                } else if (XmlStatus.WARNING == xmlConstraint.getStatus()) {
                    assertEquals(MessageTag.BBB_XCV_IVTBCTSD_ANS.getId(), xmlConstraint.getWarning().getKey());
                    ++trustAnchorSunsetCheckInvalidCounter;
                }
            } else if (MessageTag.BBB_XCV_HPCCVVT.getId().equals(xmlConstraint.getName().getKey())) {
                if (XmlStatus.OK == xmlConstraint.getStatus()) {
                    ++validProspectiveChainFoundCounter;
                } else if (XmlStatus.NOT_OK == xmlConstraint.getStatus()) {
                    assertEquals(MessageTag.BBB_XCV_HPCCVVT_ANS.getId(), xmlConstraint.getError().getKey());
                    ++ invalidProspectiveChainFoundCounter;
                }
            } else if (MessageTag.BBB_XCV_SUB.getId().equals(xmlConstraint.getName().getKey())) {
                assertNotNull(xmlConstraint.getId());
                if (XmlStatus.OK == xmlConstraint.getStatus()) {
                    ++xmlSubXCVCheckValidCounter;
                } else if (XmlStatus.NOT_OK == xmlConstraint.getStatus()) {
                    assertEquals(MessageTag.BBB_XCV_SUB_ANS.getId(), xmlConstraint.getError().getKey());
                    ++xmlSubXCVCheckInvalidCounter;
                }
            }
        }

        assertEquals(1, prospectiveChainFoundCounter);
        assertEquals(0, trustAnchorSunsetCheckValidCounter);
        assertEquals(1, trustAnchorSunsetCheckInvalidCounter);
        assertEquals(0, validProspectiveChainFoundCounter);
        assertEquals(1, invalidProspectiveChainFoundCounter);
        assertEquals(0, xmlSubXCVCheckValidCounter);
        assertEquals(0, xmlSubXCVCheckInvalidCounter);

        List<XmlSubXCV> subXCVs = xcv.getSubXCV();
        assertEquals(1, subXCVs.size());

        int untrustedCertCounter = 0;
        int trustedCertCounter = 0;
        for (XmlSubXCV subXCV : subXCVs) {
            if (subXCV.isTrustAnchor()) {
                boolean validationTimeCheckFound = false;
                boolean validProspectiveChainCheckFound = false;
                for (XmlConstraint xmlConstraint : subXCV.getConstraint()) {
                    if (MessageTag.BBB_XCV_IVTBCTSD.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.WARNING, xmlConstraint.getStatus());
                        assertEquals(MessageTag.BBB_XCV_IVTBCTSD_ANS.getId(), xmlConstraint.getWarning().getKey());
                        assertEquals(i18nProvider.getMessage(MessageTag.CERTIFICATE_SUNSET_DATE,
                                ValidationProcessUtils.getFormattedDate(xmlDiagnosticData.getValidationDate()),
                                ValidationProcessUtils.getFormattedDate(diagnosticData.getCertificateById(subXCV.getId()).getTrustSunsetDate())), xmlConstraint.getAdditionalInfo());
                        validationTimeCheckFound = true;
                    } else if (MessageTag.BBB_XCV_IOTAA.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                        assertEquals(MessageTag.BBB_XCV_IOTAA_ANS.getId(), xmlConstraint.getError().getKey());
                        validProspectiveChainCheckFound = true;
                    }
                }
                assertTrue(validationTimeCheckFound);
                assertTrue(validProspectiveChainCheckFound);
                ++trustedCertCounter;
            } else {
                ++untrustedCertCounter;
            }
        }
        assertEquals(0, untrustedCertCounter);
        assertEquals(1, trustedCertCounter);

        validateBestSigningTimes(reports);
        checkReports(reports);
    }

    @Test
    void expiredSigTstSunsetDateTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_sunset_tst_no_revoc.xml"));
        assertNotNull(xmlDiagnosticData);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();
        assertNotNull(reports);

        DiagnosticData diagnosticData = reports.getDiagnosticData();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId())));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationWarnings(simpleReport.getFirstSignatureId())));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationInfo(simpleReport.getFirstSignatureId())));

        String firstTstId = simpleReport.getSignatureTimestamps(simpleReport.getFirstSignatureId()).get(0).getId();
        assertEquals(Indication.PASSED, simpleReport.getIndication(firstTstId));

        DetailedReport detailedReport = reports.getDetailedReport();
        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertNotNull(signatureBBB);
        assertEquals(Indication.PASSED, signatureBBB.getConclusion().getIndication());

        XmlXCV xcv = signatureBBB.getXCV();
        assertNotNull(xcv);
        assertEquals(Indication.INDETERMINATE, xcv.getConclusion().getIndication());
        assertEquals(SubIndication.OUT_OF_BOUNDS_NO_POE, xcv.getConclusion().getSubIndication());
        assertTrue(checkMessageValuePresence(convert(xcv.getConclusion().getErrors()), i18nProvider.getMessage(MessageTag.BBB_XCV_SUB_ANS)));
        assertTrue(checkMessageValuePresence(convert(xcv.getConclusion().getErrors()), i18nProvider.getMessage(MessageTag.BBB_XCV_ICTIVRSC_ANS)));

        int prospectiveChainFoundCounter = 0;
        int trustAnchorSunsetCheckValidCounter = 0;
        int trustAnchorSunsetCheckInvalidCounter = 0;
        int validProspectiveChainFoundCounter = 0;
        int invalidProspectiveChainFoundCounter = 0;
        int xmlSubXCVCheckValidCounter = 0;
        int xmlSubXCVCheckInvalidCounter = 0;

        for (XmlConstraint xmlConstraint : xcv.getConstraint()) {
            if (MessageTag.BBB_XCV_CCCBB.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                ++prospectiveChainFoundCounter;
            } else if (MessageTag.BBB_XCV_IVTBCTSD.getId().equals(xmlConstraint.getName().getKey())) {
                assertNotNull(xmlConstraint.getId());
                assertEquals(i18nProvider.getMessage(MessageTag.CERTIFICATE_SUNSET_DATE_VALID), xmlConstraint.getAdditionalInfo());
                if (XmlStatus.OK == xmlConstraint.getStatus()) {
                    ++trustAnchorSunsetCheckValidCounter;
                } else if (XmlStatus.WARNING == xmlConstraint.getStatus()) {
                    assertEquals(MessageTag.BBB_XCV_IVTBCTSD_ANS.getId(), xmlConstraint.getWarning().getKey());
                    ++trustAnchorSunsetCheckInvalidCounter;
                }
            } else if (MessageTag.BBB_XCV_HPCCVVT.getId().equals(xmlConstraint.getName().getKey())) {
                if (XmlStatus.OK == xmlConstraint.getStatus()) {
                    ++validProspectiveChainFoundCounter;
                } else if (XmlStatus.NOT_OK == xmlConstraint.getStatus()) {
                    assertEquals(MessageTag.BBB_XCV_HPCCVVT_ANS.getId(), xmlConstraint.getError().getKey());
                    ++ invalidProspectiveChainFoundCounter;
                }
            } else if (MessageTag.BBB_XCV_SUB.getId().equals(xmlConstraint.getName().getKey())) {
                assertNotNull(xmlConstraint.getId());
                if (XmlStatus.OK == xmlConstraint.getStatus()) {
                    ++xmlSubXCVCheckValidCounter;
                } else if (XmlStatus.NOT_OK == xmlConstraint.getStatus()) {
                    assertEquals(MessageTag.BBB_XCV_SUB_ANS.getId(), xmlConstraint.getError().getKey());
                    ++xmlSubXCVCheckInvalidCounter;
                }
            }
        }

        assertEquals(1, prospectiveChainFoundCounter);
        assertEquals(1, trustAnchorSunsetCheckValidCounter);
        assertEquals(0, trustAnchorSunsetCheckInvalidCounter);
        assertEquals(1, validProspectiveChainFoundCounter);
        assertEquals(0, invalidProspectiveChainFoundCounter);
        assertEquals(0, xmlSubXCVCheckValidCounter);
        assertEquals(1, xmlSubXCVCheckInvalidCounter);

        List<XmlSubXCV> subXCVs = xcv.getSubXCV();
        assertEquals(2, subXCVs.size());

        int untrustedCertCounter = 0;
        int trustedCertCounter = 0;
        for (XmlSubXCV subXCV : subXCVs) {
            if (subXCV.isTrustAnchor()) {
                assertEquals(Indication.PASSED, subXCV.getConclusion().getIndication());
                ++trustedCertCounter;
            } else {
                assertEquals(Indication.INDETERMINATE, subXCV.getConclusion().getIndication());
                assertEquals(SubIndication.OUT_OF_BOUNDS_NO_POE, subXCV.getConclusion().getSubIndication());
                assertTrue(checkMessageValuePresence(convert(subXCV.getConclusion().getErrors()), i18nProvider.getMessage(MessageTag.BBB_XCV_ICTIVRSC_ANS)));
                ++untrustedCertCounter;
            }
        }
        assertEquals(1, untrustedCertCounter);
        assertEquals(1, trustedCertCounter);

        boolean signatureTstFound = false;
        boolean archiveTstFound = false;
        for (String timestampId : diagnosticData.getTimestampIdList()) {
            TimestampWrapper timestampWrapper = diagnosticData.getTimestampById(timestampId);
            XmlBasicBuildingBlocks timestampBBB = detailedReport.getBasicBuildingBlockById(timestampId);

            xcv = timestampBBB.getXCV();
            assertNotNull(xcv);

            subXCVs = xcv.getSubXCV();
            if (subXCVs.size() == 2) {
                assertEquals(Indication.INDETERMINATE, xcv.getConclusion().getIndication());
                assertEquals(SubIndication.NO_CERTIFICATE_CHAIN_FOUND_NO_POE, xcv.getConclusion().getSubIndication());
                assertTrue(checkMessageValuePresence(convert(xcv.getConclusion().getErrors()), i18nProvider.getMessage(MessageTag.BBB_XCV_IRDPFC_ANS)));
                assertTrue(checkMessageValuePresence(convert(xcv.getConclusion().getErrors()), i18nProvider.getMessage(MessageTag.BBB_XCV_SUB_ANS_2)));
                signatureTstFound = true;
            } else if (subXCVs.size() == 1) {
                assertEquals(Indication.PASSED, xcv.getConclusion().getIndication());
                archiveTstFound = true;
            }

            untrustedCertCounter = 0;
            trustedCertCounter = 0;

            boolean validTstTrustAnchorFound = false;
            boolean invalidTstTrustAnchorFound = false;
            for (XmlSubXCV subXCV : subXCVs) {
                if (subXCV.isTrustAnchor()) {
                    if (subXCVs.size() == 2) {
                        // sig tst
                        if (Indication.PASSED == subXCV.getConclusion().getIndication()) {
                            validTstTrustAnchorFound = true;

                        } else if (Indication.INDETERMINATE == subXCV.getConclusion().getIndication()) {
                            assertEquals(Indication.INDETERMINATE, subXCV.getConclusion().getIndication());
                            assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, subXCV.getConclusion().getSubIndication());
                            assertTrue(checkMessageValuePresence(convert(subXCV.getConclusion().getErrors()), i18nProvider.getMessage(MessageTag.BBB_XCV_IRDPFC_ANS)));
                            assertTrue(checkMessageValuePresence(convert(subXCV.getConclusion().getWarnings()), i18nProvider.getMessage(MessageTag.BBB_XCV_IVTBCTSD_ANS)));

                            boolean validationTimeCheckFound = false;
                            boolean validProspectiveChainCheckFound = false;
                            boolean revocationDataPresentCheckFound = false;
                            for (XmlConstraint xmlConstraint : subXCV.getConstraint()) {
                                if (MessageTag.BBB_XCV_IVTBCTSD.getId().equals(xmlConstraint.getName().getKey())) {
                                    assertEquals(XmlStatus.WARNING, xmlConstraint.getStatus());
                                    assertEquals(MessageTag.BBB_XCV_IVTBCTSD_ANS.getId(), xmlConstraint.getWarning().getKey());
                                    assertEquals(i18nProvider.getMessage(MessageTag.CERTIFICATE_SUNSET_DATE,
                                            ValidationProcessUtils.getFormattedDate(xmlDiagnosticData.getValidationDate()),
                                            ValidationProcessUtils.getFormattedDate(diagnosticData.getCertificateById(subXCV.getId()).getTrustSunsetDate())), xmlConstraint.getAdditionalInfo());
                                    validationTimeCheckFound = true;
                                } else if (MessageTag.BBB_XCV_IOTAA.getId().equals(xmlConstraint.getName().getKey())) {
                                    assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                                    validProspectiveChainCheckFound = true;
                                } else if (MessageTag.BBB_XCV_IRDPFC.getId().equals(xmlConstraint.getName().getKey())) {
                                    assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                                    assertEquals(MessageTag.BBB_XCV_IRDPFC_ANS.getId(), xmlConstraint.getError().getKey());
                                    revocationDataPresentCheckFound = true;
                                }
                            }
                            assertTrue(validationTimeCheckFound);
                            assertTrue(validProspectiveChainCheckFound);
                            assertTrue(revocationDataPresentCheckFound);

                            invalidTstTrustAnchorFound = true;
                        }

                    } else {
                        // arc tst
                        assertEquals(Indication.PASSED, subXCV.getConclusion().getIndication());

                        boolean validationTimeCheckFound = false;
                        boolean validProspectiveChainCheckFound = false;
                        for (XmlConstraint xmlConstraint : subXCV.getConstraint()) {
                            if (MessageTag.BBB_XCV_IVTBCTSD.getId().equals(xmlConstraint.getName().getKey())) {
                                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                                assertEquals(i18nProvider.getMessage(MessageTag.CERTIFICATE_SUNSET_DATE_VALID), xmlConstraint.getAdditionalInfo());
                                validationTimeCheckFound = true;
                            } else if (MessageTag.BBB_XCV_IOTAA.getId().equals(xmlConstraint.getName().getKey())) {
                                validProspectiveChainCheckFound = true;
                            }
                        }
                        assertTrue(validationTimeCheckFound);
                        assertFalse(validProspectiveChainCheckFound);
                    }
                    ++trustedCertCounter;
                } else {
                    ++untrustedCertCounter;
                }
            }
            if (subXCVs.size() == 2) {
                assertEquals(0, untrustedCertCounter);
                assertEquals(2, trustedCertCounter);
                assertTrue(validTstTrustAnchorFound);
                assertTrue(invalidTstTrustAnchorFound);

                XmlPSV psv = timestampBBB.getPSV();
                assertNotNull(psv);
                assertEquals(Indication.PASSED, psv.getConclusion().getIndication());

                boolean revocationCheckFound = false;
                boolean pastCertValFound = false;
                for (XmlConstraint xmlConstraint : psv.getConstraint()) {
                    assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                    if (MessageTag.BBB_XCV_IARDPFC.getId().equals(xmlConstraint.getName().getKey())) {
                        revocationCheckFound = true;
                    } else if (MessageTag.PSV_IPCVA.getId().equals(xmlConstraint.getName().getKey())) {
                        pastCertValFound = true;
                    }
                }
                assertFalse(revocationCheckFound);
                assertTrue(pastCertValFound);

                assertNull(timestampBBB.getPSVCRS());

                XmlPCV pcv = timestampBBB.getPCV();
                assertNotNull(pcv);
                assertEquals(Indication.PASSED, pcv.getConclusion().getIndication());

                int vtsCheckSuccessFound = 0;
                int vtsCheckFailureFound = 0;
                int certChainVtsCheckFound = 0;
                for (XmlConstraint xmlConstraint : pcv.getConstraint()) {
                    if (MessageTag.PCV_IVTSC.getId().equals(xmlConstraint.getName().getKey())) {
                        if (XmlStatus.OK == xmlConstraint.getStatus()) {
                            assertEquals(i18nProvider.getMessage(MessageTag.CONTROL_TIME_WITH_TRUST_ANCHOR, timestampWrapper.getSigningCertificate().getId(),
                                    ValidationProcessUtils.getFormattedDate(timestampWrapper.getSigningCertificate().getTrustSunsetDate())), xmlConstraint.getAdditionalInfo());
                            ++vtsCheckSuccessFound;
                        } else if (XmlStatus.WARNING == xmlConstraint.getStatus()) {
                            assertEquals(MessageTag.PCV_IVTSC_ANS.getId(), xmlConstraint.getWarning().getKey());
                            assertEquals(i18nProvider.getMessage(MessageTag.CONTROL_TIME_WITH_TRUST_ANCHOR, timestampWrapper.getSigningCertificate().getSigningCertificate().getId(),
                                    ValidationProcessUtils.getFormattedDate(diagnosticData.getValidationDate())), xmlConstraint.getAdditionalInfo());
                            ++vtsCheckFailureFound;
                        }

                    } else if (MessageTag.PCV_ICCSVTSF.getId().equals(xmlConstraint.getName().getKey())) {
                        ++certChainVtsCheckFound;
                    } else {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                    }
                }
                assertEquals(1, vtsCheckSuccessFound);
                assertEquals(1, vtsCheckFailureFound);
                assertEquals(1, certChainVtsCheckFound);

                XmlVTS vts = timestampBBB.getVTS();
                assertNotNull(vts);
                assertEquals(Indication.PASSED, vts.getConclusion().getIndication());

            } else {
                assertEquals(1, trustedCertCounter);
            }

        }
        assertTrue(signatureTstFound);
        assertTrue(archiveTstFound);

        validateBestSigningTimes(reports);
        checkReports(reports);
    }

    @Test
    void expiredSigTstArcTstAfterSunsetDateTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_sunset_tst_no_revoc.xml"));
        assertNotNull(xmlDiagnosticData);

        Calendar calendar = Calendar.getInstance();
        calendar.set(2018, Calendar.JANUARY, 1, 0, 0, 0);
        Date tstProductionTime = calendar.getTime();

        xmlDiagnosticData.getUsedTimestamps().get(1).setProductionTime(tstProductionTime);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();
        assertNotNull(reports);

        DiagnosticData diagnosticData = reports.getDiagnosticData();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.OUT_OF_BOUNDS_NO_POE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_XCV_ICTIVRSC_ANS)));

        String firstTstId = simpleReport.getSignatureTimestamps(simpleReport.getFirstSignatureId()).get(0).getId();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(firstTstId));
        assertEquals(SubIndication.NO_CERTIFICATE_CHAIN_FOUND_NO_POE, simpleReport.getSubIndication(firstTstId));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(firstTstId),
                i18nProvider.getMessage(MessageTag.BBB_XCV_SUB_ANS_2)));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(firstTstId),
                i18nProvider.getMessage(MessageTag.BBB_XCV_IRDPFC_ANS)));

        String secondTstId = simpleReport.getSignatureTimestamps(simpleReport.getFirstSignatureId()).get(1).getId();
        assertEquals(Indication.PASSED, simpleReport.getIndication(secondTstId));

        DetailedReport detailedReport = reports.getDetailedReport();
        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertNotNull(signatureBBB);
        assertEquals(Indication.INDETERMINATE, signatureBBB.getConclusion().getIndication());
        assertEquals(SubIndication.OUT_OF_BOUNDS_NO_POE, signatureBBB.getConclusion().getSubIndication());
        assertTrue(checkMessageValuePresence(convert(signatureBBB.getConclusion().getErrors()), i18nProvider.getMessage(MessageTag.BBB_XCV_ICTIVRSC_ANS)));

        XmlXCV xcv = signatureBBB.getXCV();
        assertNotNull(xcv);
        assertEquals(Indication.INDETERMINATE, xcv.getConclusion().getIndication());
        assertEquals(SubIndication.OUT_OF_BOUNDS_NO_POE, xcv.getConclusion().getSubIndication());
        assertTrue(checkMessageValuePresence(convert(xcv.getConclusion().getErrors()), i18nProvider.getMessage(MessageTag.BBB_XCV_SUB_ANS)));
        assertTrue(checkMessageValuePresence(convert(xcv.getConclusion().getErrors()), i18nProvider.getMessage(MessageTag.BBB_XCV_ICTIVRSC_ANS)));

        int prospectiveChainFoundCounter = 0;
        int trustAnchorSunsetCheckValidCounter = 0;
        int trustAnchorSunsetCheckInvalidCounter = 0;
        int validProspectiveChainFoundCounter = 0;
        int invalidProspectiveChainFoundCounter = 0;
        int xmlSubXCVCheckValidCounter = 0;
        int xmlSubXCVCheckInvalidCounter = 0;

        for (XmlConstraint xmlConstraint : xcv.getConstraint()) {
            if (MessageTag.BBB_XCV_CCCBB.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                ++prospectiveChainFoundCounter;
            } else if (MessageTag.BBB_XCV_IVTBCTSD.getId().equals(xmlConstraint.getName().getKey())) {
                assertNotNull(xmlConstraint.getId());
                assertEquals(i18nProvider.getMessage(MessageTag.CERTIFICATE_SUNSET_DATE_VALID), xmlConstraint.getAdditionalInfo());
                if (XmlStatus.OK == xmlConstraint.getStatus()) {
                    ++trustAnchorSunsetCheckValidCounter;
                } else if (XmlStatus.WARNING == xmlConstraint.getStatus()) {
                    assertEquals(MessageTag.BBB_XCV_IVTBCTSD_ANS.getId(), xmlConstraint.getWarning().getKey());
                    ++trustAnchorSunsetCheckInvalidCounter;
                }
            } else if (MessageTag.BBB_XCV_HPCCVVT.getId().equals(xmlConstraint.getName().getKey())) {
                if (XmlStatus.OK == xmlConstraint.getStatus()) {
                    ++validProspectiveChainFoundCounter;
                } else if (XmlStatus.NOT_OK == xmlConstraint.getStatus()) {
                    assertEquals(MessageTag.BBB_XCV_HPCCVVT_ANS.getId(), xmlConstraint.getError().getKey());
                    ++ invalidProspectiveChainFoundCounter;
                }
            } else if (MessageTag.BBB_XCV_SUB.getId().equals(xmlConstraint.getName().getKey())) {
                assertNotNull(xmlConstraint.getId());
                if (XmlStatus.OK == xmlConstraint.getStatus()) {
                    ++xmlSubXCVCheckValidCounter;
                } else if (XmlStatus.NOT_OK == xmlConstraint.getStatus()) {
                    assertEquals(MessageTag.BBB_XCV_SUB_ANS.getId(), xmlConstraint.getError().getKey());
                    ++xmlSubXCVCheckInvalidCounter;
                }
            }
        }

        assertEquals(1, prospectiveChainFoundCounter);
        assertEquals(1, trustAnchorSunsetCheckValidCounter);
        assertEquals(0, trustAnchorSunsetCheckInvalidCounter);
        assertEquals(1, validProspectiveChainFoundCounter);
        assertEquals(0, invalidProspectiveChainFoundCounter);
        assertEquals(0, xmlSubXCVCheckValidCounter);
        assertEquals(1, xmlSubXCVCheckInvalidCounter);

        List<XmlSubXCV> subXCVs = xcv.getSubXCV();
        assertEquals(2, subXCVs.size());

        int untrustedCertCounter = 0;
        int trustedCertCounter = 0;
        for (XmlSubXCV subXCV : subXCVs) {
            if (subXCV.isTrustAnchor()) {
                assertEquals(Indication.PASSED, subXCV.getConclusion().getIndication());
                ++trustedCertCounter;
            } else {
                assertEquals(Indication.INDETERMINATE, subXCV.getConclusion().getIndication());
                assertEquals(SubIndication.OUT_OF_BOUNDS_NO_POE, subXCV.getConclusion().getSubIndication());
                assertTrue(checkMessageValuePresence(convert(subXCV.getConclusion().getErrors()), i18nProvider.getMessage(MessageTag.BBB_XCV_ICTIVRSC_ANS)));
                ++untrustedCertCounter;
            }
        }
        assertEquals(1, untrustedCertCounter);
        assertEquals(1, trustedCertCounter);

        boolean signatureTstFound = false;
        boolean archiveTstFound = false;
        for (String timestampId : diagnosticData.getTimestampIdList()) {
            TimestampWrapper timestampWrapper = diagnosticData.getTimestampById(timestampId);
            XmlBasicBuildingBlocks timestampBBB = detailedReport.getBasicBuildingBlockById(timestampId);

            xcv = timestampBBB.getXCV();
            assertNotNull(xcv);

            subXCVs = xcv.getSubXCV();
            if (subXCVs.size() == 2) {
                assertEquals(Indication.INDETERMINATE, xcv.getConclusion().getIndication());
                assertEquals(SubIndication.NO_CERTIFICATE_CHAIN_FOUND_NO_POE, xcv.getConclusion().getSubIndication());
                assertTrue(checkMessageValuePresence(convert(xcv.getConclusion().getErrors()), i18nProvider.getMessage(MessageTag.BBB_XCV_IRDPFC_ANS)));
                assertTrue(checkMessageValuePresence(convert(xcv.getConclusion().getErrors()), i18nProvider.getMessage(MessageTag.BBB_XCV_SUB_ANS_2)));
                signatureTstFound = true;
            } else if (subXCVs.size() == 1) {
                assertEquals(Indication.PASSED, xcv.getConclusion().getIndication());
                archiveTstFound = true;
            }

            untrustedCertCounter = 0;
            trustedCertCounter = 0;

            boolean validTstTrustAnchorFound = false;
            boolean invalidTstTrustAnchorFound = false;
            for (XmlSubXCV subXCV : subXCVs) {
                if (subXCV.isTrustAnchor()) {
                    if (subXCVs.size() == 2) {
                        // sig tst
                        if (Indication.PASSED == subXCV.getConclusion().getIndication()) {
                            validTstTrustAnchorFound = true;

                        } else if (Indication.INDETERMINATE == subXCV.getConclusion().getIndication()) {
                            assertEquals(Indication.INDETERMINATE, subXCV.getConclusion().getIndication());
                            assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, subXCV.getConclusion().getSubIndication());
                            assertTrue(checkMessageValuePresence(convert(subXCV.getConclusion().getErrors()), i18nProvider.getMessage(MessageTag.BBB_XCV_IRDPFC_ANS)));
                            assertTrue(checkMessageValuePresence(convert(subXCV.getConclusion().getWarnings()), i18nProvider.getMessage(MessageTag.BBB_XCV_IVTBCTSD_ANS)));

                            boolean validationTimeCheckFound = false;
                            boolean validProspectiveChainCheckFound = false;
                            boolean revocationDataPresentCheckFound = false;
                            for (XmlConstraint xmlConstraint : subXCV.getConstraint()) {
                                if (MessageTag.BBB_XCV_IVTBCTSD.getId().equals(xmlConstraint.getName().getKey())) {
                                    assertEquals(XmlStatus.WARNING, xmlConstraint.getStatus());
                                    assertEquals(MessageTag.BBB_XCV_IVTBCTSD_ANS.getId(), xmlConstraint.getWarning().getKey());
                                    assertEquals(i18nProvider.getMessage(MessageTag.CERTIFICATE_SUNSET_DATE,
                                            ValidationProcessUtils.getFormattedDate(xmlDiagnosticData.getValidationDate()),
                                            ValidationProcessUtils.getFormattedDate(diagnosticData.getCertificateById(subXCV.getId()).getTrustSunsetDate())), xmlConstraint.getAdditionalInfo());
                                    validationTimeCheckFound = true;
                                } else if (MessageTag.BBB_XCV_IOTAA.getId().equals(xmlConstraint.getName().getKey())) {
                                    assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                                    validProspectiveChainCheckFound = true;
                                } else if (MessageTag.BBB_XCV_IRDPFC.getId().equals(xmlConstraint.getName().getKey())) {
                                    assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                                    assertEquals(MessageTag.BBB_XCV_IRDPFC_ANS.getId(), xmlConstraint.getError().getKey());
                                    revocationDataPresentCheckFound = true;
                                }
                            }
                            assertTrue(validationTimeCheckFound);
                            assertTrue(validProspectiveChainCheckFound);
                            assertTrue(revocationDataPresentCheckFound);

                            invalidTstTrustAnchorFound = true;
                        }

                    } else {
                        // arc tst
                        assertEquals(Indication.PASSED, subXCV.getConclusion().getIndication());

                        boolean validationTimeCheckFound = false;
                        boolean validProspectiveChainCheckFound = false;
                        for (XmlConstraint xmlConstraint : subXCV.getConstraint()) {
                            if (MessageTag.BBB_XCV_IVTBCTSD.getId().equals(xmlConstraint.getName().getKey())) {
                                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                                assertEquals(i18nProvider.getMessage(MessageTag.CERTIFICATE_SUNSET_DATE_VALID), xmlConstraint.getAdditionalInfo());
                                validationTimeCheckFound = true;
                            } else if (MessageTag.BBB_XCV_IOTAA.getId().equals(xmlConstraint.getName().getKey())) {
                                validProspectiveChainCheckFound = true;
                            }
                        }
                        assertTrue(validationTimeCheckFound);
                        assertFalse(validProspectiveChainCheckFound);
                    }
                    ++trustedCertCounter;
                } else {
                    ++untrustedCertCounter;
                }
            }
            if (subXCVs.size() == 2) {
                assertEquals(0, untrustedCertCounter);
                assertEquals(2, trustedCertCounter);
                assertTrue(validTstTrustAnchorFound);
                assertTrue(invalidTstTrustAnchorFound);

                XmlPSV psv = timestampBBB.getPSV();
                assertNotNull(psv);
                assertEquals(Indication.INDETERMINATE, psv.getConclusion().getIndication());
                assertEquals(SubIndication.NO_CERTIFICATE_CHAIN_FOUND_NO_POE, psv.getConclusion().getSubIndication());

                boolean revocationCheckFound = false;
                boolean pastCertValFound = false;
                boolean poeCheckFound = false;
                boolean currentTimeValCheckFound = false;
                for (XmlConstraint xmlConstraint : psv.getConstraint()) {
                    if (MessageTag.BBB_XCV_IARDPFC.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.WARNING, xmlConstraint.getStatus());
                        assertEquals(MessageTag.BBB_XCV_IARDPFC_ANS.getId(), xmlConstraint.getWarning().getKey());
                        revocationCheckFound = true;
                    } else if (MessageTag.PSV_IPCVA.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        assertEquals(i18nProvider.getMessage(MessageTag.CONTROL_TIME_ALONE, ValidationProcessUtils.getFormattedDate(
                                timestampWrapper.getSigningCertificate().getTrustSunsetDate())), xmlConstraint.getAdditionalInfo());
                        pastCertValFound = true;
                    } else if (MessageTag.PSV_ITPOSVAOBCT.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.WARNING, xmlConstraint.getStatus());
                        assertEquals(MessageTag.PSV_ITPOSVAOBCT_ANS.getId(), xmlConstraint.getWarning().getKey());
                        assertEquals(i18nProvider.getMessage(MessageTag.CONTROL_TIME_WITH_POE,
                                ValidationProcessUtils.getFormattedDate(timestampWrapper.getSigningCertificate().getTrustSunsetDate()),
                                ValidationProcessUtils.getFormattedDate(diagnosticData.getTimestampList().get(1).getProductionTime())), xmlConstraint.getAdditionalInfo());
                        poeCheckFound = true;
                    } else if (MessageTag.PSV_IPCVC.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                        assertEquals(MessageTag.PSV_IPCVC_ANS.getId(), xmlConstraint.getError().getKey());
                        currentTimeValCheckFound = true;
                    }
                }
                assertTrue(revocationCheckFound);
                assertTrue(pastCertValFound);
                assertTrue(poeCheckFound);
                assertTrue(currentTimeValCheckFound);

                XmlCRS psvcrs = timestampBBB.getPSVCRS();
                assertNotNull(psvcrs);
                assertEquals(Indication.INDETERMINATE, psvcrs.getConclusion().getIndication());
                assertEquals(SubIndication.TRY_LATER, psvcrs.getConclusion().getSubIndication());

                XmlPCV pcv = timestampBBB.getPCV();
                assertNotNull(pcv);
                assertEquals(Indication.PASSED, pcv.getConclusion().getIndication());

                int vtsCheckSuccessFound = 0;
                int vtsCheckFailureFound = 0;
                int certChainVtsCheckFound = 0;
                for (XmlConstraint xmlConstraint : pcv.getConstraint()) {
                    if (MessageTag.PCV_IVTSC.getId().equals(xmlConstraint.getName().getKey())) {
                        if (XmlStatus.OK == xmlConstraint.getStatus()) {
                            assertEquals(i18nProvider.getMessage(MessageTag.CONTROL_TIME_WITH_TRUST_ANCHOR, timestampWrapper.getSigningCertificate().getId(),
                                    ValidationProcessUtils.getFormattedDate(timestampWrapper.getSigningCertificate().getTrustSunsetDate())), xmlConstraint.getAdditionalInfo());
                            ++vtsCheckSuccessFound;
                        } else if (XmlStatus.WARNING == xmlConstraint.getStatus()) {
                            assertEquals(MessageTag.PCV_IVTSC_ANS.getId(), xmlConstraint.getWarning().getKey());
                            assertEquals(i18nProvider.getMessage(MessageTag.CONTROL_TIME_WITH_TRUST_ANCHOR, timestampWrapper.getSigningCertificate().getSigningCertificate().getId(),
                                    ValidationProcessUtils.getFormattedDate(diagnosticData.getValidationDate())), xmlConstraint.getAdditionalInfo());
                            ++vtsCheckFailureFound;
                        }

                    } else if (MessageTag.PCV_ICCSVTSF.getId().equals(xmlConstraint.getName().getKey())) {
                        ++certChainVtsCheckFound;
                    } else {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                    }
                }
                assertEquals(1, vtsCheckSuccessFound);
                assertEquals(1, vtsCheckFailureFound);
                assertEquals(1, certChainVtsCheckFound);

                XmlVTS vts = timestampBBB.getVTS();
                assertNotNull(vts);
                assertEquals(Indication.PASSED, vts.getConclusion().getIndication());
                assertEquals(timestampWrapper.getSigningCertificate().getTrustSunsetDate(), vts.getControlTime());
                assertEquals(timestampWrapper.getSigningCertificate().getId(), vts.getTrustAnchor());

            } else {
                assertEquals(1, trustedCertCounter);
            }

        }
        assertTrue(signatureTstFound);
        assertTrue(archiveTstFound);

        validateBestSigningTimes(reports);
        checkReports(reports);
    }

    @Test
    void qualWithdrawnService() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_sunset_withdrawn.xml"));
        assertNotNull(xmlDiagnosticData);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();
        assertNotNull(reports);

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.NO_CERTIFICATE_CHAIN_FOUND, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SignatureQualification.INDETERMINATE_ADESIG, simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()));

        DetailedReport detailedReport = reports.getDetailedReport();
        XmlSignature xmlSignature = detailedReport.getSignatures().get(0);

        XmlValidationSignatureQualification validationSignatureQualification = xmlSignature.getValidationSignatureQualification();
        assertNotNull(validationSignatureQualification);
        assertEquals(SignatureQualification.INDETERMINATE_ADESIG, validationSignatureQualification.getSignatureQualification());

        boolean adesValidationCheckFound = false;
        boolean trustedListReached = false;
        for (XmlConstraint constraint : validationSignatureQualification.getConstraint()) {
            if (MessageTag.QUAL_IS_ADES.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.WARNING, constraint.getStatus());
                assertEquals(MessageTag.QUAL_IS_ADES_IND.getId(), constraint.getWarning().getKey());
                adesValidationCheckFound = true;
            } else if (MessageTag.QUAL_CERT_TRUSTED_LIST_REACHED.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                trustedListReached = true;
            }
        }
        assertTrue(adesValidationCheckFound);
        assertTrue(trustedListReached);

        List<XmlValidationCertificateQualification> validationCertificateQualification = validationSignatureQualification
                .getValidationCertificateQualification();
        assertEquals(2, validationCertificateQualification.size());

        boolean qualAtCertIssuanceTimeFound = false;
        boolean qualAtBSTFound = false;
        for (XmlValidationCertificateQualification certificateQualification : validationCertificateQualification) {
            if (ValidationTime.CERTIFICATE_ISSUANCE_TIME == certificateQualification.getValidationTime()) {
                qualAtCertIssuanceTimeFound = true;
            } else if (ValidationTime.BEST_SIGNATURE_TIME == certificateQualification.getValidationTime()) {
                qualAtBSTFound = true;
            }
            assertEquals(CertificateQualification.CERT_FOR_ESIG, certificateQualification.getCertificateQualification());
        }
        assertTrue(qualAtCertIssuanceTimeFound);
        assertTrue(qualAtBSTFound);
    }

    @Test
    void qualWithdrawnServiceTrusted() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_sunset_withdrawn.xml"));
        assertNotNull(xmlDiagnosticData);

        XmlCertificate caCertificate = xmlDiagnosticData.getSignatures().get(0).getCertificateChain().get(1).getCertificate();
        caCertificate.getTrusted().setValue(true);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();
        assertNotNull(reports);

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SignatureQualification.ADESIG, simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()));

        DetailedReport detailedReport = reports.getDetailedReport();
        XmlSignature xmlSignature = detailedReport.getSignatures().get(0);

        XmlValidationSignatureQualification validationSignatureQualification = xmlSignature.getValidationSignatureQualification();
        assertNotNull(validationSignatureQualification);
        assertEquals(SignatureQualification.ADESIG, validationSignatureQualification.getSignatureQualification());

        boolean adesValidationCheckFound = false;
        boolean trustedListReached = false;
        for (XmlConstraint constraint : validationSignatureQualification.getConstraint()) {
            if (MessageTag.QUAL_IS_ADES.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                adesValidationCheckFound = true;
            } else if (MessageTag.QUAL_CERT_TRUSTED_LIST_REACHED.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                trustedListReached = true;
            }
        }
        assertTrue(adesValidationCheckFound);
        assertTrue(trustedListReached);

        List<XmlValidationCertificateQualification> validationCertificateQualification = validationSignatureQualification
                .getValidationCertificateQualification();
        assertEquals(2, validationCertificateQualification.size());

        boolean qualAtCertIssuanceTimeFound = false;
        boolean qualAtBSTFound = false;
        for (XmlValidationCertificateQualification certificateQualification : validationCertificateQualification) {
            if (ValidationTime.CERTIFICATE_ISSUANCE_TIME == certificateQualification.getValidationTime()) {
                qualAtCertIssuanceTimeFound = true;
            } else if (ValidationTime.BEST_SIGNATURE_TIME == certificateQualification.getValidationTime()) {
                qualAtBSTFound = true;
            }
            assertEquals(CertificateQualification.CERT_FOR_ESIG, certificateQualification.getCertificateQualification());
        }
        assertTrue(qualAtCertIssuanceTimeFound);
        assertTrue(qualAtBSTFound);
    }

    @Test
    void qualWithdrawnServiceTrustedWithSunset() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_sunset_withdrawn.xml"));
        assertNotNull(xmlDiagnosticData);

        XmlCertificate caCertificate = xmlDiagnosticData.getSignatures().get(0).getCertificateChain().get(1).getCertificate();
        caCertificate.getTrusted().setValue(true);

        Calendar calendar = Calendar.getInstance();
        calendar.set(2025, Calendar.JANUARY, 1 , 0, 0, 0);
        caCertificate.getTrusted().setSunsetDate(calendar.getTime());

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();
        assertNotNull(reports);

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SignatureQualification.ADESIG, simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()));

        DetailedReport detailedReport = reports.getDetailedReport();
        XmlSignature xmlSignature = detailedReport.getSignatures().get(0);

        XmlValidationSignatureQualification validationSignatureQualification = xmlSignature.getValidationSignatureQualification();
        assertNotNull(validationSignatureQualification);
        assertEquals(SignatureQualification.ADESIG, validationSignatureQualification.getSignatureQualification());

        boolean adesValidationCheckFound = false;
        boolean trustedListReached = false;
        for (XmlConstraint constraint : validationSignatureQualification.getConstraint()) {
            if (MessageTag.QUAL_IS_ADES.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                adesValidationCheckFound = true;
            } else if (MessageTag.QUAL_CERT_TRUSTED_LIST_REACHED.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                trustedListReached = true;
            }
        }
        assertTrue(adesValidationCheckFound);
        assertTrue(trustedListReached);

        List<XmlValidationCertificateQualification> validationCertificateQualification = validationSignatureQualification
                .getValidationCertificateQualification();
        assertEquals(2, validationCertificateQualification.size());

        boolean qualAtCertIssuanceTimeFound = false;
        boolean qualAtBSTFound = false;
        for (XmlValidationCertificateQualification certificateQualification : validationCertificateQualification) {
            if (ValidationTime.CERTIFICATE_ISSUANCE_TIME == certificateQualification.getValidationTime()) {
                qualAtCertIssuanceTimeFound = true;
            } else if (ValidationTime.BEST_SIGNATURE_TIME == certificateQualification.getValidationTime()) {
                qualAtBSTFound = true;
            }
            assertEquals(CertificateQualification.CERT_FOR_ESIG, certificateQualification.getCertificateQualification());
        }
        assertTrue(qualAtCertIssuanceTimeFound);
        assertTrue(qualAtBSTFound);
    }

    @Test
    void qualWithdrawnServiceTrustedWithSunsetExpired() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_sunset_withdrawn.xml"));
        assertNotNull(xmlDiagnosticData);

        XmlCertificate caCertificate = xmlDiagnosticData.getSignatures().get(0).getCertificateChain().get(1).getCertificate();
        caCertificate.getTrusted().setValue(true);

        Calendar calendar = Calendar.getInstance();
        calendar.set(2024, Calendar.JANUARY, 1 , 0, 0, 0);
        caCertificate.getTrusted().setSunsetDate(calendar.getTime());

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();
        assertNotNull(reports);

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.NO_CERTIFICATE_CHAIN_FOUND_NO_POE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SignatureQualification.INDETERMINATE_ADESIG, simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()));

        DetailedReport detailedReport = reports.getDetailedReport();
        XmlSignature xmlSignature = detailedReport.getSignatures().get(0);

        XmlValidationSignatureQualification validationSignatureQualification = xmlSignature.getValidationSignatureQualification();
        assertNotNull(validationSignatureQualification);
        assertEquals(SignatureQualification.INDETERMINATE_ADESIG, validationSignatureQualification.getSignatureQualification());

        boolean adesValidationCheckFound = false;
        boolean trustedListReached = false;
        for (XmlConstraint constraint : validationSignatureQualification.getConstraint()) {
            if (MessageTag.QUAL_IS_ADES.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.WARNING, constraint.getStatus());
                assertEquals(MessageTag.QUAL_IS_ADES_IND.getId(), constraint.getWarning().getKey());
                adesValidationCheckFound = true;
            } else if (MessageTag.QUAL_CERT_TRUSTED_LIST_REACHED.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                trustedListReached = true;
            }
        }
        assertTrue(adesValidationCheckFound);
        assertTrue(trustedListReached);

        List<XmlValidationCertificateQualification> validationCertificateQualification = validationSignatureQualification
                .getValidationCertificateQualification();
        assertEquals(2, validationCertificateQualification.size());

        boolean qualAtCertIssuanceTimeFound = false;
        boolean qualAtBSTFound = false;
        for (XmlValidationCertificateQualification certificateQualification : validationCertificateQualification) {
            if (ValidationTime.CERTIFICATE_ISSUANCE_TIME == certificateQualification.getValidationTime()) {
                qualAtCertIssuanceTimeFound = true;
            } else if (ValidationTime.BEST_SIGNATURE_TIME == certificateQualification.getValidationTime()) {
                qualAtBSTFound = true;
            }
            assertEquals(CertificateQualification.CERT_FOR_ESIG, certificateQualification.getCertificateQualification());
        }
        assertTrue(qualAtCertIssuanceTimeFound);
        assertTrue(qualAtBSTFound);
    }

}
