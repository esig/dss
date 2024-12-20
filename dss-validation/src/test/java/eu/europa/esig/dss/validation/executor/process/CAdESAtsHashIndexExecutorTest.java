package eu.europa.esig.dss.validation.executor.process;

import eu.europa.esig.dss.detailedreport.DetailedReport;
import eu.europa.esig.dss.detailedreport.jaxb.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlFC;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.diagnostic.DiagnosticDataFacade;
import eu.europa.esig.dss.diagnostic.jaxb.XmlArchiveTimestampHashIndex;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTimestamp;
import eu.europa.esig.dss.enumerations.ArchiveTimestampHashIndexVersion;
import eu.europa.esig.dss.enumerations.ArchiveTimestampType;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.ValidationPolicy;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.executor.signature.DefaultSignatureProcessExecutor;
import eu.europa.esig.dss.validation.reports.Reports;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class CAdESAtsHashIndexExecutorTest extends AbstractProcessExecutorTest {

    @Test
    void atsHashIndexFailValidTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/diag-data/dss-1469-diag-data.xml"));
        assertNotNull(diagnosticData);

        List<XmlTimestamp> usedTimestamps = diagnosticData.getUsedTimestamps();
        assertEquals(2, usedTimestamps.size());

        XmlTimestamp archiveTst = diagnosticData.getUsedTimestamps().get(diagnosticData.getUsedTimestamps().size() - 1);
        archiveTst.setArchiveTimestampType(ArchiveTimestampType.CAdES_V3);

        XmlArchiveTimestampHashIndex xmlArchiveTimestampHashIndex = new XmlArchiveTimestampHashIndex();
        xmlArchiveTimestampHashIndex.setVersion(ArchiveTimestampHashIndexVersion.ATS_HASH_INDEX_V3);
        xmlArchiveTimestampHashIndex.setValid(true);
        archiveTst.setArchiveTimestampHashIndex(xmlArchiveTimestampHashIndex);

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);
        validationPolicy.getTimestampConstraints().setAtsHashIndex(constraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        for (eu.europa.esig.dss.simplereport.jaxb.XmlTimestamp xmlTimestamp : simpleReport.getSignatureTimestamps(simpleReport.getFirstSignatureId())) {
            assertEquals(Indication.PASSED, xmlTimestamp.getIndication());
            assertTrue(Utils.isCollectionEmpty(xmlTimestamp.getAdESValidationDetails().getError()));
        }

        DetailedReport detailedReport = reports.getDetailedReport();

        boolean sigTstFound = false;
        boolean arcTstFound = false;
        for (XmlTimestamp timestamp : usedTimestamps) {
            XmlBasicBuildingBlocks tstBBB = detailedReport.getBasicBuildingBlockById(timestamp.getId());
            assertNotNull(tstBBB);

            XmlFC fc = tstBBB.getFC();
            if (fc == null) {
                sigTstFound = true;
                continue;
            } else {
                arcTstFound = true;
            }

            assertEquals(Indication.PASSED, fc.getConclusion().getIndication());

            boolean atsHashIndexCheckFound = false;
            for (XmlConstraint xmlConstraint : fc.getConstraint()) {
                if (MessageTag.BBB_FC_IAHIV.getId().equals(xmlConstraint.getName().getKey())) {
                    assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                    atsHashIndexCheckFound = true;
                } else {
                    assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                }
            }
            assertTrue(atsHashIndexCheckFound);
        }
        assertTrue(sigTstFound);
        assertTrue(arcTstFound);


        checkReports(reports);
    }

    @Test
    void atsHashIndexFailInvalidTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/diag-data/dss-1469-diag-data.xml"));
        assertNotNull(diagnosticData);

        List<XmlTimestamp> usedTimestamps = diagnosticData.getUsedTimestamps();
        assertEquals(2, usedTimestamps.size());

        XmlTimestamp archiveTst = diagnosticData.getUsedTimestamps().get(diagnosticData.getUsedTimestamps().size() - 1);
        archiveTst.setArchiveTimestampType(ArchiveTimestampType.CAdES_V3);

        XmlArchiveTimestampHashIndex xmlArchiveTimestampHashIndex = new XmlArchiveTimestampHashIndex();
        xmlArchiveTimestampHashIndex.setVersion(ArchiveTimestampHashIndexVersion.ATS_HASH_INDEX_V3);
        xmlArchiveTimestampHashIndex.setValid(false);
        archiveTst.setArchiveTimestampHashIndex(xmlArchiveTimestampHashIndex);

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);
        validationPolicy.getTimestampConstraints().setAtsHashIndex(constraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));

        boolean sigTstFound = false;
        boolean arcTstFound = false;
        for (eu.europa.esig.dss.simplereport.jaxb.XmlTimestamp xmlTimestamp : simpleReport.getSignatureTimestamps(simpleReport.getFirstSignatureId())) {
            if (Indication.PASSED == xmlTimestamp.getIndication()) {
                sigTstFound = true;
            } else if (Indication.FAILED == xmlTimestamp.getIndication()) {
                assertEquals(SubIndication.FORMAT_FAILURE, xmlTimestamp.getSubIndication());
                assertTrue(checkMessageValuePresence(convertMessages(xmlTimestamp.getAdESValidationDetails().getError()),
                        i18nProvider.getMessage(MessageTag.BBB_FC_IAHIV_ANS)));
                arcTstFound = true;
            }
        }
        assertTrue(sigTstFound);
        assertTrue(arcTstFound);

        DetailedReport detailedReport = reports.getDetailedReport();

        sigTstFound = false;
        arcTstFound = false;

        for (XmlTimestamp timestamp : usedTimestamps) {
            XmlBasicBuildingBlocks tstBBB = detailedReport.getBasicBuildingBlockById(timestamp.getId());
            assertNotNull(tstBBB);

            XmlFC fc = tstBBB.getFC();
            if (fc == null) {
                sigTstFound = true;
                continue;
            } else {
                arcTstFound = true;
            }

            assertEquals(Indication.FAILED, fc.getConclusion().getIndication());
            assertEquals(SubIndication.FORMAT_FAILURE, fc.getConclusion().getSubIndication());

            boolean atsHashIndexCheckFound = false;
            for (XmlConstraint xmlConstraint : fc.getConstraint()) {
                if (MessageTag.BBB_FC_IAHIV.getId().equals(xmlConstraint.getName().getKey())) {
                    assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                    assertEquals(MessageTag.BBB_FC_IAHIV_ANS.getId(), xmlConstraint.getError().getKey());
                    atsHashIndexCheckFound = true;
                } else {
                    assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                }
            }
            assertTrue(atsHashIndexCheckFound);
        }
        assertTrue(sigTstFound);
        assertTrue(arcTstFound);


        checkReports(reports);
    }

    @Test
    void atsHashIndexWarnValidTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/diag-data/dss-1469-diag-data.xml"));
        assertNotNull(diagnosticData);

        List<XmlTimestamp> usedTimestamps = diagnosticData.getUsedTimestamps();
        assertEquals(2, usedTimestamps.size());

        XmlTimestamp archiveTst = diagnosticData.getUsedTimestamps().get(diagnosticData.getUsedTimestamps().size() - 1);
        archiveTst.setArchiveTimestampType(ArchiveTimestampType.CAdES_V3);

        XmlArchiveTimestampHashIndex xmlArchiveTimestampHashIndex = new XmlArchiveTimestampHashIndex();
        xmlArchiveTimestampHashIndex.setVersion(ArchiveTimestampHashIndexVersion.ATS_HASH_INDEX_V3);
        xmlArchiveTimestampHashIndex.setValid(true);
        archiveTst.setArchiveTimestampHashIndex(xmlArchiveTimestampHashIndex);

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.WARN);
        validationPolicy.getTimestampConstraints().setAtsHashIndex(constraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        for (eu.europa.esig.dss.simplereport.jaxb.XmlTimestamp xmlTimestamp : simpleReport.getSignatureTimestamps(simpleReport.getFirstSignatureId())) {
            assertEquals(Indication.PASSED, xmlTimestamp.getIndication());
            assertTrue(Utils.isCollectionEmpty(xmlTimestamp.getAdESValidationDetails().getError()));
        }

        DetailedReport detailedReport = reports.getDetailedReport();

        boolean sigTstFound = false;
        boolean arcTstFound = false;
        for (XmlTimestamp timestamp : usedTimestamps) {
            XmlBasicBuildingBlocks tstBBB = detailedReport.getBasicBuildingBlockById(timestamp.getId());
            assertNotNull(tstBBB);

            XmlFC fc = tstBBB.getFC();
            if (fc == null) {
                sigTstFound = true;
                continue;
            } else {
                arcTstFound = true;
            }

            assertEquals(Indication.PASSED, fc.getConclusion().getIndication());

            boolean atsHashIndexCheckFound = false;
            for (XmlConstraint xmlConstraint : fc.getConstraint()) {
                if (MessageTag.BBB_FC_IAHIV.getId().equals(xmlConstraint.getName().getKey())) {
                    assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                    atsHashIndexCheckFound = true;
                } else {
                    assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                }
            }
            assertTrue(atsHashIndexCheckFound);
        }
        assertTrue(sigTstFound);
        assertTrue(arcTstFound);


        checkReports(reports);
    }

    @Test
    void atsHashIndexWarnInvalidTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/diag-data/dss-1469-diag-data.xml"));
        assertNotNull(diagnosticData);

        List<XmlTimestamp> usedTimestamps = diagnosticData.getUsedTimestamps();
        assertEquals(2, usedTimestamps.size());

        XmlTimestamp archiveTst = diagnosticData.getUsedTimestamps().get(diagnosticData.getUsedTimestamps().size() - 1);
        archiveTst.setArchiveTimestampType(ArchiveTimestampType.CAdES_V3);

        XmlArchiveTimestampHashIndex xmlArchiveTimestampHashIndex = new XmlArchiveTimestampHashIndex();
        xmlArchiveTimestampHashIndex.setVersion(ArchiveTimestampHashIndexVersion.ATS_HASH_INDEX_V3);
        xmlArchiveTimestampHashIndex.setValid(false);
        archiveTst.setArchiveTimestampHashIndex(xmlArchiveTimestampHashIndex);

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.WARN);
        validationPolicy.getTimestampConstraints().setAtsHashIndex(constraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));

        boolean sigTstFound = false;
        boolean arcTstFound = false;
        for (eu.europa.esig.dss.simplereport.jaxb.XmlTimestamp xmlTimestamp : simpleReport.getSignatureTimestamps(simpleReport.getFirstSignatureId())) {
            assertEquals(Indication.PASSED, xmlTimestamp.getIndication());
            assertTrue(Utils.isCollectionEmpty(xmlTimestamp.getAdESValidationDetails().getError()));
            if (checkMessageValuePresence(convertMessages(xmlTimestamp.getAdESValidationDetails().getWarning()),
                    i18nProvider.getMessage(MessageTag.BBB_FC_IAHIV_ANS))) {
                arcTstFound = true;
            } else {
                sigTstFound = true;
            }
        }
        assertTrue(sigTstFound);
        assertTrue(arcTstFound);

        DetailedReport detailedReport = reports.getDetailedReport();

        sigTstFound = false;
        arcTstFound = false;

        for (XmlTimestamp timestamp : usedTimestamps) {
            XmlBasicBuildingBlocks tstBBB = detailedReport.getBasicBuildingBlockById(timestamp.getId());
            assertNotNull(tstBBB);

            XmlFC fc = tstBBB.getFC();
            if (fc == null) {
                sigTstFound = true;
                continue;
            } else {
                arcTstFound = true;
            }

            assertEquals(Indication.PASSED, fc.getConclusion().getIndication());
            assertTrue(Utils.isCollectionEmpty(fc.getConclusion().getErrors()));
            assertTrue(checkMessageValuePresence(convert(fc.getConclusion().getWarnings()),
                    i18nProvider.getMessage(MessageTag.BBB_FC_IAHIV_ANS)));

            boolean atsHashIndexCheckFound = false;
            for (XmlConstraint xmlConstraint : fc.getConstraint()) {
                if (MessageTag.BBB_FC_IAHIV.getId().equals(xmlConstraint.getName().getKey())) {
                    assertEquals(XmlStatus.WARNING, xmlConstraint.getStatus());
                    assertEquals(MessageTag.BBB_FC_IAHIV_ANS.getId(), xmlConstraint.getWarning().getKey());
                    atsHashIndexCheckFound = true;
                } else {
                    assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                }
            }
            assertTrue(atsHashIndexCheckFound);
        }
        assertTrue(sigTstFound);
        assertTrue(arcTstFound);


        checkReports(reports);
    }

    @Test
    void atsHashIndexInvalidSkipTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/diag-data/dss-1469-diag-data.xml"));
        assertNotNull(diagnosticData);

        List<XmlTimestamp> usedTimestamps = diagnosticData.getUsedTimestamps();
        assertEquals(2, usedTimestamps.size());

        XmlTimestamp archiveTst = diagnosticData.getUsedTimestamps().get(diagnosticData.getUsedTimestamps().size() - 1);
        archiveTst.setArchiveTimestampType(ArchiveTimestampType.CAdES_V3);

        XmlArchiveTimestampHashIndex xmlArchiveTimestampHashIndex = new XmlArchiveTimestampHashIndex();
        xmlArchiveTimestampHashIndex.setVersion(ArchiveTimestampHashIndexVersion.ATS_HASH_INDEX_V3);
        xmlArchiveTimestampHashIndex.setValid(false);
        archiveTst.setArchiveTimestampHashIndex(xmlArchiveTimestampHashIndex);

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        validationPolicy.getTimestampConstraints().setAtsHashIndex(null);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        for (eu.europa.esig.dss.simplereport.jaxb.XmlTimestamp xmlTimestamp : simpleReport.getSignatureTimestamps(simpleReport.getFirstSignatureId())) {
            assertEquals(Indication.PASSED, xmlTimestamp.getIndication());
            assertTrue(Utils.isCollectionEmpty(xmlTimestamp.getAdESValidationDetails().getError()));
        }

        DetailedReport detailedReport = reports.getDetailedReport();
        for (XmlTimestamp timestamp : usedTimestamps) {
            XmlBasicBuildingBlocks tstBBB = detailedReport.getBasicBuildingBlockById(timestamp.getId());
            assertNotNull(tstBBB);

            XmlFC fc = tstBBB.getFC();
            assertNull(fc);
        }

        checkReports(reports);
    }

}
