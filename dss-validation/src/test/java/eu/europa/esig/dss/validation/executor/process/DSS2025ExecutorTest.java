/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.validation.executor.process;

import eu.europa.esig.dss.detailedreport.DetailedReport;
import eu.europa.esig.dss.detailedreport.jaxb.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSubXCV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlXCV;
import eu.europa.esig.dss.diagnostic.DiagnosticDataFacade;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTimestamp;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.Level;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.EtsiValidationPolicy;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.policy.jaxb.SignatureConstraints;
import eu.europa.esig.dss.policy.jaxb.SignedAttributesConstraints;
import eu.europa.esig.dss.policy.jaxb.TimestampConstraints;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.validation.executor.signature.DefaultSignatureProcessExecutor;
import eu.europa.esig.dss.validation.reports.Reports;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DSS2025ExecutorTest extends AbstractProcessExecutorTest {

    @Test
    void dss2025() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/DSS-2025/diag-sign-cert-tst-not-unique.xml"));
        assertNotNull(diagnosticData);

        EtsiValidationPolicy validationPolicy = loadDefaultPolicy();
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.WARN);
        validationPolicy.getTimestampConstraints().getBasicSignatureConstraints()
                .getSigningCertificate().setIssuerName(constraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();
        // reports.print();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));

        eu.europa.esig.dss.simplereport.jaxb.XmlTimestamp xmlTimestamp = simpleReport.getSignatureTimestamps(simpleReport.getFirstSignatureId()).get(0);
        assertEquals(Indication.PASSED, xmlTimestamp.getIndication());
        assertTrue(checkMessageValuePresence(convertMessages(xmlTimestamp.getAdESValidationDetails().getWarning()),
                i18nProvider.getMessage(MessageTag.BBB_XCV_DCIDNMSDNIC_ANS)));
    }

    @Test
    void dss2025TstFailLevel() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/DSS-2025/diag-sign-cert-tst-not-unique.xml"));
        assertNotNull(diagnosticData);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);

        EtsiValidationPolicy defaultPolicy = loadDefaultPolicy();
        TimestampConstraints timestampConstraints = defaultPolicy.getTimestampConstraints();
        SignedAttributesConstraints signedAttributes = timestampConstraints.getSignedAttributes();

        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.FAIL);
        signedAttributes.setUnicitySigningCertificate(levelConstraint);

        levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.WARN);
        defaultPolicy.getTimestampConstraints().getBasicSignatureConstraints()
                .getSigningCertificate().setIssuerName(levelConstraint);

        executor.setValidationPolicy(defaultPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        List<XmlTimestamp> usedTimestamps = diagnosticData.getUsedTimestamps();
        assertEquals(1, usedTimestamps.size());
        String tstId = usedTimestamps.get(0).getId();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.INDETERMINATE, detailedReport.getBasicTimestampValidationIndication(tstId));
        assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, detailedReport.getBasicTimestampValidationSubIndication(tstId));
    }

    @Test
    void dss2025Unique() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/DSS-2025/diag-sign-cert-unique.xml"));
        assertNotNull(diagnosticData);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);

        EtsiValidationPolicy defaultPolicy = loadDefaultPolicy();
        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.FAIL);
        SignatureConstraints signatureConstraints = defaultPolicy.getSignatureConstraints();
        SignedAttributesConstraints sigSignedAttributes = signatureConstraints.getSignedAttributes();
        sigSignedAttributes.setUnicitySigningCertificate(levelConstraint);
        TimestampConstraints timestampConstraints = defaultPolicy.getTimestampConstraints();
        SignedAttributesConstraints tstSignedAttributes = timestampConstraints.getSignedAttributes();
        tstSignedAttributes.setUnicitySigningCertificate(levelConstraint);

        levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.WARN);
        defaultPolicy.getTimestampConstraints().getBasicSignatureConstraints()
                .getSigningCertificate().setIssuerName(levelConstraint);

        executor.setValidationPolicy(defaultPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();
        // reports.print();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
    }

    @Test
    void dss2025WithOrphanFail() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/DSS-2025/diag-sign-cert-with-orphan.xml"));
        assertNotNull(diagnosticData);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);

        EtsiValidationPolicy defaultPolicy = loadDefaultPolicy();
        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.FAIL);
        SignatureConstraints signatureConstraints = defaultPolicy.getSignatureConstraints();
        SignedAttributesConstraints sigSignedAttributes = signatureConstraints.getSignedAttributes();
        sigSignedAttributes.setUnicitySigningCertificate(levelConstraint);

        levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.WARN);
        defaultPolicy.getTimestampConstraints().getBasicSignatureConstraints()
                .getSigningCertificate().setIssuerName(levelConstraint);

        executor.setValidationPolicy(defaultPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();
        // reports.print();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
    }

    @Test
    void dss2025AnotherCertSignCertRef() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/DSS-2025/diag-sign-cert-another-cert.xml"));
        assertNotNull(diagnosticData);

        EtsiValidationPolicy validationPolicy = loadDefaultPolicy();
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.WARN);
        validationPolicy.getTimestampConstraints().getBasicSignatureConstraints()
                .getSigningCertificate().setIssuerName(constraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();
        // reports.print();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.NO_SIGNING_CERTIFICATE_FOUND, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
    }

    @Test
    void dss2025TstIssuerNameFailLevel() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/DSS-2025/diag-sign-cert-tst-not-unique.xml"));
        assertNotNull(diagnosticData);

        EtsiValidationPolicy validationPolicy = loadDefaultPolicy();
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(Level.FAIL);
        validationPolicy.getTimestampConstraints().getBasicSignatureConstraints()
                .getSigningCertificate().setIssuerName(constraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();
        // reports.print();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));

        eu.europa.esig.dss.simplereport.jaxb.XmlTimestamp xmlTimestamp = simpleReport.getSignatureTimestamps(simpleReport.getFirstSignatureId()).get(0);
        assertEquals(Indication.INDETERMINATE, xmlTimestamp.getIndication());
        assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, xmlTimestamp.getSubIndication());
        assertTrue(checkMessageValuePresence(convertMessages(xmlTimestamp.getAdESValidationDetails().getError()),
                i18nProvider.getMessage(MessageTag.BBB_XCV_DCIDNMSDNIC_ANS)));

        DetailedReport detailedReport = reports.getDetailedReport();
        XmlBasicBuildingBlocks tstBBB = detailedReport.getBasicBuildingBlockById(xmlTimestamp.getId());
        assertNotNull(tstBBB);

        XmlXCV xcv = tstBBB.getXCV();
        assertNotNull(xcv);
        List<XmlSubXCV> subXCVs = xcv.getSubXCV();
        assertEquals(2, subXCVs.size());

        XmlSubXCV xmlSubXCV = subXCVs.get(0);
        boolean issuerNameCheckFound = false;
        for (XmlConstraint xmlConstraint : xmlSubXCV.getConstraint()) {
            if (MessageTag.BBB_XCV_DCIDNMSDNIC.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                assertEquals(MessageTag.BBB_XCV_DCIDNMSDNIC_ANS.getId(), xmlConstraint.getError().getKey());
                issuerNameCheckFound = true;
            } else {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
            }
        }
        assertTrue(issuerNameCheckFound);
    }

}
