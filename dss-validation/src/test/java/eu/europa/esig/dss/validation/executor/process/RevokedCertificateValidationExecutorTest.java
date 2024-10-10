/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * 
 * This file is part of the "DSS - Digital Signature Services" project.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.validation.executor.process;

import eu.europa.esig.dss.detailedreport.DetailedReport;
import eu.europa.esig.dss.detailedreport.jaxb.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.detailedreport.jaxb.XmlCRS;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlPCV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlPSV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlRAC;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSubXCV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlVTS;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessLongTermData;
import eu.europa.esig.dss.detailedreport.jaxb.XmlXCV;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.DiagnosticDataFacade;
import eu.europa.esig.dss.diagnostic.RevocationWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.EtsiValidationPolicy;
import eu.europa.esig.dss.policy.jaxb.ConstraintsParameters;
import eu.europa.esig.dss.policy.jaxb.Model;
import eu.europa.esig.dss.policy.jaxb.ModelConstraint;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.executor.signature.DefaultSignatureProcessExecutor;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.validationreport.enums.ObjectType;
import eu.europa.esig.validationreport.jaxb.POEType;
import eu.europa.esig.validationreport.jaxb.ValidationObjectListType;
import eu.europa.esig.validationreport.jaxb.ValidationObjectType;
import eu.europa.esig.validationreport.jaxb.ValidationReportType;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.util.List;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RevokedCertificateValidationExecutorTest extends AbstractProcessExecutorTest {

    @Test
    void noPoeRevokedNoTimestamp() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/diag-data/no_poe_revoked_no_timestamp.xml"));
        assertNotNull(diagnosticData);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();
        // reports.print();
        assertNotNull(reports);

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.REVOKED_NO_POE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.INDETERMINATE, detailedReport.getBasicValidationIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.REVOKED_NO_POE, detailedReport.getBasicValidationSubIndication(simpleReport.getFirstSignatureId()));

        assertEquals(0, detailedReport.getTimestampIds().size());

        assertEquals(Indication.INDETERMINATE, detailedReport.getLongTermValidationIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.REVOKED_NO_POE, detailedReport.getLongTermValidationSubIndication(simpleReport.getFirstSignatureId()));

        assertEquals(Indication.INDETERMINATE, detailedReport.getArchiveDataValidationIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.REVOKED_NO_POE, detailedReport.getArchiveDataValidationSubIndication(simpleReport.getFirstSignatureId()));

        validateBestSigningTimes(reports);
        checkReports(reports);
    }

    @Test
    void revokedValidationInPast() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/diag-data/no_poe_revoked_no_timestamp.xml"));
        assertNotNull(diagnosticData);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getSignatures().get(0).getSigningCertificate().getCertificate().getNotBefore());

        Reports reports = executor.execute();
        assertNotNull(reports);

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.REVOCATION_OUT_OF_BOUNDS_NO_POE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
    }

    @Test
    void passedRevokedWithTimestamp() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/diag-data/passed_revoked_with_timestamp.xml"));
        assertNotNull(diagnosticData);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();
        assertNotNull(reports);

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.INDETERMINATE, detailedReport.getBasicValidationIndication(detailedReport.getFirstSignatureId()));
        assertEquals(SubIndication.REVOKED_NO_POE, detailedReport.getBasicValidationSubIndication(detailedReport.getFirstSignatureId()));

        List<String> timestampIds = detailedReport.getTimestampIds();
        assertEquals(1, timestampIds.size());

        assertEquals(Indication.PASSED, detailedReport.getBasicTimestampValidationIndication(timestampIds.get(0)));

        assertEquals(Indication.PASSED, detailedReport.getLongTermValidationIndication(simpleReport.getFirstSignatureId()));

        assertEquals(Indication.PASSED, detailedReport.getArchiveDataValidationIndication(simpleReport.getFirstSignatureId()));

        validateBestSigningTimes(reports);
        checkReports(reports);
    }

    @Test
    void passedOutOfBoundsWithTimestamps() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/diag-data/passed_out_of_bounds_with_timestamps.xml"));
        assertNotNull(diagnosticData);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();
        assertNotNull(reports);

//		reports.print();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.INDETERMINATE, detailedReport.getBasicValidationIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, detailedReport.getBasicValidationSubIndication(simpleReport.getFirstSignatureId()));

        List<String> timestampIds = detailedReport.getTimestampIds();
        assertEquals(5, timestampIds.size());
        for (String tspId : timestampIds) {
            assertEquals(Indication.PASSED, detailedReport.getBasicTimestampValidationIndication(tspId));
        }

        assertEquals(Indication.PASSED, detailedReport.getLongTermValidationIndication(simpleReport.getFirstSignatureId()));

        assertEquals(Indication.PASSED, detailedReport.getArchiveDataValidationIndication(simpleReport.getFirstSignatureId()));

        ValidationReportType etsiValidationReport = reports.getEtsiValidationReportJaxb();
        ValidationObjectListType signatureValidationObjects = etsiValidationReport.getSignatureValidationObjects();
        assertNotNull(signatureValidationObjects);
        assertTrue(Utils.isCollectionNotEmpty(signatureValidationObjects.getValidationObject()));

        TimestampWrapper firstArchiveTst = null;
        for (TimestampWrapper timestampWrapper : reports.getDiagnosticData().getTimestampList()) {
            if (TimestampType.ARCHIVE_TIMESTAMP.equals(timestampWrapper.getType())) {
                if (firstArchiveTst == null) {
                    firstArchiveTst = timestampWrapper;
                } else if (timestampWrapper.getProductionTime().before(firstArchiveTst.getProductionTime())) {
                    firstArchiveTst = timestampWrapper;
                } else if (timestampWrapper.getProductionTime().compareTo(firstArchiveTst.getProductionTime()) == 0 &&
                        timestampWrapper.getTimestampedObjects().size() < firstArchiveTst.getTimestampedObjects().size()) {
                    firstArchiveTst = timestampWrapper;
                }
            }
        }
        assertNotNull(firstArchiveTst);

        List<String> timestampedRevocationIds = firstArchiveTst.getTimestampedRevocations().stream().map(RevocationWrapper::getId)
                .collect(Collectors.toList());

        int timestampedRevocationsCounter = 0;
        for (ValidationObjectType validationObject : signatureValidationObjects.getValidationObject()) {
            if (ObjectType.CRL.equals(validationObject.getObjectType())) {
                assertNotNull(validationObject.getId());
                POEType poe = validationObject.getPOE();
                assertNotNull(poe);
                assertNotNull(poe.getPOETime());
                assertNotNull(poe.getTypeOfProof());
                if (timestampedRevocationIds.contains(validationObject.getId())) {
                    assertNotNull(poe.getPOEObject());
                    assertEquals(1, poe.getPOEObject().getVOReference().size());
                    Object poeObject = poe.getPOEObject().getVOReference().get(0);
                    assertInstanceOf(ValidationObjectType.class, poeObject);
                    assertEquals(firstArchiveTst.getId(), ((ValidationObjectType) poeObject).getId());
                    assertEquals(firstArchiveTst.getProductionTime(), poe.getPOETime());
                    ++timestampedRevocationsCounter;
                }
            }
        }
        assertEquals(2, timestampedRevocationsCounter);

        validateBestSigningTimes(reports);
        checkReports(reports);
    }

    @Test
    void revokedWithNotTrustedOCSP() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/diag-data/revoked_ocsp_not_trusted.xml"));
        assertNotNull(diagnosticData);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();
        assertNotNull(reports);

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));

        DetailedReport detailedReport = reports.getDetailedReport();
        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertNotNull(signatureBBB);

        XmlXCV xcv = signatureBBB.getXCV();
        assertEquals(Indication.INDETERMINATE, xcv.getConclusion().getIndication());
        assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, xcv.getConclusion().getSubIndication());

        XmlSubXCV xmlSubXCV = xcv.getSubXCV().get(0);
        assertNotNull(xmlSubXCV);
        List<XmlRAC> xmlRACs = xmlSubXCV.getCRS().getRAC();
        assertEquals(1, xmlRACs.size());
        XmlRAC xmlRAC = xmlRACs.get(0);
        assertEquals(Indication.INDETERMINATE, xmlRAC.getConclusion().getIndication());
        assertEquals(SubIndication.NO_CERTIFICATE_CHAIN_FOUND, xmlRAC.getConclusion().getSubIndication());

        XmlCRS crs = xmlSubXCV.getCRS();
        assertNotNull(crs);
        assertTrue(checkMessageValuePresence(convert(crs.getConclusion().getErrors()),
                i18nProvider.getMessage(MessageTag.BBB_XCV_IARDPFC_ANS)));
        List<XmlConstraint> crsConstraints = crs.getConstraint();
        XmlConstraint constraint = crsConstraints.get(crsConstraints.size() - 1);
        assertEquals(MessageTag.BBB_XCV_IARDPFC.name(), constraint.getName().getKey());
        assertEquals(i18nProvider.getMessage(MessageTag.BBB_XCV_IARDPFC_ANS), constraint.getError().getValue());
        assertEquals(Indication.INDETERMINATE, crs.getConclusion().getIndication());
        assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, crs.getConclusion().getSubIndication());
    }

    @Test
    void revokedNotYetValidWithTimestamp() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/diag-data/revoked-not-yet-valid-with-timestamp.xml"));
        assertNotNull(diagnosticData);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();
        assertNotNull(reports);

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_FAILED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.NOT_YET_VALID, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.TSV_IBSTAIDOSC_ANS)));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.INDETERMINATE, detailedReport.getBasicValidationIndication(detailedReport.getFirstSignatureId()));
        assertEquals(SubIndication.REVOKED_NO_POE, detailedReport.getBasicValidationSubIndication(detailedReport.getFirstSignatureId()));

        List<String> timestampIds = detailedReport.getTimestampIds();
        assertEquals(1, timestampIds.size());

        assertEquals(Indication.PASSED, detailedReport.getBasicTimestampValidationIndication(timestampIds.get(0)));

        assertEquals(Indication.FAILED, detailedReport.getLongTermValidationIndication(detailedReport.getFirstSignatureId()));
        assertEquals(SubIndication.NOT_YET_VALID, detailedReport.getLongTermValidationSubIndication(detailedReport.getFirstSignatureId()));

        eu.europa.esig.dss.detailedreport.jaxb.XmlSignature xmlSignature = detailedReport.getXmlSignatureById(detailedReport.getFirstSignatureId());
        assertNotNull(xmlSignature);

        XmlValidationProcessLongTermData ltv = xmlSignature.getValidationProcessLongTermData();
        assertNotNull(ltv);

        assertEquals(Indication.FAILED, ltv.getConclusion().getIndication());
        assertEquals(SubIndication.NOT_YET_VALID, ltv.getConclusion().getSubIndication());

        boolean revocationPosteriorToBSTCheckFound = false;
        boolean bstBeforeIssuanceSignCertCheckFound = false;
        for (XmlConstraint constraint : ltv.getConstraint()) {
            if (MessageTag.ADEST_IRTPTBST.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                revocationPosteriorToBSTCheckFound = true;
            } else if (MessageTag.TSV_IBSTAIDOSC.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
                assertEquals(MessageTag.TSV_IBSTAIDOSC_ANS.getId(), constraint.getError().getKey());
                bstBeforeIssuanceSignCertCheckFound = true;
            } else {
                assertEquals(XmlStatus.OK, constraint.getStatus());
            }
        }
        assertTrue(revocationPosteriorToBSTCheckFound);
        assertTrue(bstBeforeIssuanceSignCertCheckFound);

        validateBestSigningTimes(reports);
        checkReports(reports);
    }

    @Test
    void revokedExpiredWithTimestamp() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/diag-data/revoked-expired-with-timestamp.xml"));
        assertNotNull(diagnosticData);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();
        assertNotNull(reports);

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.TSV_IBSTBCEC_ANS)));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.INDETERMINATE, detailedReport.getBasicValidationIndication(detailedReport.getFirstSignatureId()));
        assertEquals(SubIndication.REVOKED_NO_POE, detailedReport.getBasicValidationSubIndication(detailedReport.getFirstSignatureId()));

        List<String> timestampIds = detailedReport.getTimestampIds();
        assertEquals(1, timestampIds.size());

        assertEquals(Indication.PASSED, detailedReport.getBasicTimestampValidationIndication(timestampIds.get(0)));

        assertEquals(Indication.INDETERMINATE, detailedReport.getLongTermValidationIndication(detailedReport.getFirstSignatureId()));
        assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, detailedReport.getLongTermValidationSubIndication(detailedReport.getFirstSignatureId()));

        eu.europa.esig.dss.detailedreport.jaxb.XmlSignature xmlSignature = detailedReport.getXmlSignatureById(detailedReport.getFirstSignatureId());
        assertNotNull(xmlSignature);

        XmlValidationProcessLongTermData ltv = xmlSignature.getValidationProcessLongTermData();
        assertNotNull(ltv);

        assertEquals(Indication.INDETERMINATE, ltv.getConclusion().getIndication());
        assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, ltv.getConclusion().getSubIndication());

        boolean revocationPosteriorToBSTCheckFound = false;
        boolean bstBeforeIssuanceSignCertCheckFound = false;
        boolean bstBeforeExpirationSignCertCheckFound = false;
        for (XmlConstraint constraint : ltv.getConstraint()) {
            if (MessageTag.ADEST_IRTPTBST.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                revocationPosteriorToBSTCheckFound = true;
            } else if (MessageTag.TSV_IBSTAIDOSC.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, constraint.getStatus());
                bstBeforeIssuanceSignCertCheckFound = true;
            } else if (MessageTag.TSV_IBSTBCEC.getId().equals(constraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, constraint.getStatus());
                assertEquals(MessageTag.TSV_IBSTBCEC_ANS.getId(), constraint.getError().getKey());
                bstBeforeExpirationSignCertCheckFound = true;
            } else {
                assertEquals(XmlStatus.OK, constraint.getStatus());
            }
        }
        assertTrue(revocationPosteriorToBSTCheckFound);
        assertTrue(bstBeforeIssuanceSignCertCheckFound);
        assertTrue(bstBeforeExpirationSignCertCheckFound);

        validateBestSigningTimes(reports);
        checkReports(reports);
    }

    @Test
    void revokedCATest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/diag-data/ca-revoked.xml"));
        assertNotNull(xmlDiagnosticData);

        ConstraintsParameters constraintsParameters = getConstraintsParameters(new File("src/test/resources/diag-data/policy/default-only-constraint-policy.xml"));
        ModelConstraint modelConstraint = new ModelConstraint();
        modelConstraint.setValue(Model.SHELL);
        constraintsParameters.setModel(modelConstraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(new EtsiValidationPolicy(constraintsParameters));
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();
        assertNotNull(reports);

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.REVOKED_CA_NO_POE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.INDETERMINATE, detailedReport.getBasicValidationIndication(detailedReport.getFirstSignatureId()));
        assertEquals(SubIndication.REVOKED_CA_NO_POE, detailedReport.getBasicValidationSubIndication(detailedReport.getFirstSignatureId()));

        assertEquals(Indication.INDETERMINATE, detailedReport.getLongTermValidationIndication(detailedReport.getFirstSignatureId()));
        assertEquals(SubIndication.REVOKED_CA_NO_POE, detailedReport.getLongTermValidationSubIndication(detailedReport.getFirstSignatureId()));

        assertEquals(Indication.INDETERMINATE, detailedReport.getArchiveDataValidationIndication(detailedReport.getFirstSignatureId()));
        assertEquals(SubIndication.REVOKED_CA_NO_POE, detailedReport.getArchiveDataValidationSubIndication(detailedReport.getFirstSignatureId()));

        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        XmlXCV xcv = signatureBBB.getXCV();
        assertNotNull(xcv);

        DiagnosticData diagnosticData = reports.getDiagnosticData();
        SignatureWrapper signatureWrapper = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        CertificateWrapper signingCertificate = signatureWrapper.getSigningCertificate();
        assertNotNull(signingCertificate);

        List<XmlSubXCV> subXCVs = xcv.getSubXCV();
        XmlSubXCV xmlSubXCV = subXCVs.get(0);
        assertEquals(signingCertificate.getId(), xmlSubXCV.getId());
        assertEquals(Indication.PASSED, xmlSubXCV.getConclusion().getIndication());

        xmlSubXCV = subXCVs.get(1);
        assertEquals(signingCertificate.getSigningCertificate().getId(), xmlSubXCV.getId());
        assertEquals(Indication.INDETERMINATE, xmlSubXCV.getConclusion().getIndication());
        assertEquals(SubIndication.REVOKED_CA_NO_POE, xmlSubXCV.getConclusion().getSubIndication());

        XmlPCV pcv = signatureBBB.getPCV();
        assertNull(pcv);

        XmlVTS vts = signatureBBB.getVTS();
        assertNull(vts);

        XmlPSV psv = signatureBBB.getPSV();
        assertNull(psv);
    }

    @Test
    void revokedCAChainModelTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/diag-data/ca-revoked.xml"));
        assertNotNull(xmlDiagnosticData);

        ConstraintsParameters constraintsParameters = getConstraintsParameters(new File("src/test/resources/diag-data/policy/default-only-constraint-policy.xml"));
        ModelConstraint modelConstraint = new ModelConstraint();
        modelConstraint.setValue(Model.CHAIN);
        constraintsParameters.setModel(modelConstraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(new EtsiValidationPolicy(constraintsParameters));
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();
        assertNotNull(reports);

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
    }

    @Test
    void revokedCAHybridModelTest() throws Exception {
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/diag-data/ca-revoked.xml"));
        assertNotNull(xmlDiagnosticData);

        ConstraintsParameters constraintsParameters = getConstraintsParameters(new File("src/test/resources/diag-data/policy/default-only-constraint-policy.xml"));
        ModelConstraint modelConstraint = new ModelConstraint();
        modelConstraint.setValue(Model.HYBRID);
        constraintsParameters.setModel(modelConstraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(xmlDiagnosticData);
        executor.setValidationPolicy(new EtsiValidationPolicy(constraintsParameters));
        executor.setCurrentTime(xmlDiagnosticData.getValidationDate());

        Reports reports = executor.execute();
        assertNotNull(reports);

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
    }

}
