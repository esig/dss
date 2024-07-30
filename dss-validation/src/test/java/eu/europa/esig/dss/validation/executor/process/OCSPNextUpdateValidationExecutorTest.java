package eu.europa.esig.dss.validation.executor.process;

import eu.europa.esig.dss.detailedreport.DetailedReport;
import eu.europa.esig.dss.detailedreport.jaxb.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlRFC;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSubXCV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlXCV;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.DiagnosticDataFacade;
import eu.europa.esig.dss.diagnostic.RevocationWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.RevocationType;
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
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class OCSPNextUpdateValidationExecutorTest extends AbstractProcessExecutorTest {

    @Test
    void nextUpdateCheckTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/valid-diag-data.xml"));
        assertNotNull(xmlDiagnosticData);

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        BasicSignatureConstraints basicSigConstraints = validationPolicy.getSignatureConstraints().getBasicSignatureConstraints();
        basicSigConstraints.getSigningCertificate().setOCSPNextUpdatePresent(null);
        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.FAIL);
        basicSigConstraints.getCACertificate().setCRLNextUpdatePresent(levelConstraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();
        DiagnosticData diagnosticData = reports.getDiagnosticData();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));

        DetailedReport detailedReport = reports.getDetailedReport();
        XmlBasicBuildingBlocks sigBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        XmlXCV xcv = sigBBB.getXCV();
        List<XmlSubXCV> subXCVs = xcv.getSubXCV();
        assertEquals(3, subXCVs.size());

        boolean signCertFound = false;
        boolean caCertFound = false;
        boolean rootCertFound = false;
        for (XmlSubXCV subXCV : subXCVs) {
            XmlRFC rfc = subXCV.getRFC();
            if (rfc != null) {
                RevocationWrapper revocation = diagnosticData.getRevocationById(rfc.getId());
                assertNotNull(revocation);
                if (RevocationType.OCSP.equals(revocation.getRevocationType())) {
                    signCertFound = true;

                    boolean nextUpdateCheckPerformed = false;
                    List<XmlConstraint> constraints = rfc.getConstraint();
                    for (XmlConstraint constraint : constraints) {
                        if (MessageTag.BBB_RFC_NUP.getId().equals(constraint.getName().getKey())) {
                            nextUpdateCheckPerformed = true;
                            break;
                        }
                    }
                    assertFalse(nextUpdateCheckPerformed);

                } else if (RevocationType.CRL.equals(revocation.getRevocationType())) {
                    caCertFound = true;

                    boolean nextUpdateCheckPerformed = false;
                    List<XmlConstraint> constraints = rfc.getConstraint();
                    for (XmlConstraint constraint : constraints) {
                        if (MessageTag.BBB_RFC_NUP.getId().equals(constraint.getName().getKey())) {
                            nextUpdateCheckPerformed = true;
                            assertEquals(XmlStatus.OK, constraint.getStatus());
                        }
                    }
                    assertTrue(nextUpdateCheckPerformed);
                }
            } else {
                rootCertFound = true;
            }
        }
        assertTrue(signCertFound);
        assertTrue(caCertFound);
        assertTrue(rootCertFound);
    }

    @Test
    void nextUpdateCheckOCSPFailTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/valid-diag-data.xml"));
        assertNotNull(xmlDiagnosticData);

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        BasicSignatureConstraints basicSigConstraints = validationPolicy.getSignatureConstraints().getBasicSignatureConstraints();
        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.FAIL);
        basicSigConstraints.getSigningCertificate().setOCSPNextUpdatePresent(levelConstraint);
        basicSigConstraints.getCACertificate().setCRLNextUpdatePresent(null);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();
        DiagnosticData diagnosticData = reports.getDiagnosticData();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.TRY_LATER, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));

        DetailedReport detailedReport = reports.getDetailedReport();
        XmlBasicBuildingBlocks sigBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        XmlXCV xcv = sigBBB.getXCV();
        List<XmlSubXCV> subXCVs = xcv.getSubXCV();
        assertEquals(3, subXCVs.size());

        boolean signCertFound = false;
        boolean caCertFound = false;
        boolean rootCertFound = false;
        for (XmlSubXCV subXCV : subXCVs) {
            XmlRFC rfc = subXCV.getRFC();
            if (rfc != null) {
                RevocationWrapper revocation = diagnosticData.getRevocationById(rfc.getId());
                assertNotNull(revocation);
                if (RevocationType.OCSP.equals(revocation.getRevocationType())) {
                    signCertFound = true;

                    boolean nextUpdateCheckPerformed = false;
                    List<XmlConstraint> constraints = rfc.getConstraint();
                    for (XmlConstraint constraint : constraints) {
                        if (MessageTag.BBB_RFC_NUP.getId().equals(constraint.getName().getKey())) {
                            nextUpdateCheckPerformed = true;
                            assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
                            assertEquals(MessageTag.BBB_RFC_NUP_ANS.getId(), constraint.getError().getKey());
                        }
                    }
                    assertTrue(nextUpdateCheckPerformed);

                } else if (RevocationType.CRL.equals(revocation.getRevocationType())) {
                    caCertFound = true;

                    boolean nextUpdateCheckPerformed = false;
                    List<XmlConstraint> constraints = rfc.getConstraint();
                    for (XmlConstraint constraint : constraints) {
                        if (MessageTag.BBB_RFC_NUP.getId().equals(constraint.getName().getKey())) {
                            nextUpdateCheckPerformed = true;
                            assertEquals(XmlStatus.OK, constraint.getStatus());
                        }
                    }
                    assertFalse(nextUpdateCheckPerformed);
                }
            } else {
                rootCertFound = true;
            }
        }
        assertTrue(signCertFound);
        assertTrue(caCertFound);
        assertTrue(rootCertFound);
    }

}
