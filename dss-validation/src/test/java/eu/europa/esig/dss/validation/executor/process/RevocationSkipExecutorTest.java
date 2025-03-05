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
import eu.europa.esig.dss.detailedreport.jaxb.XmlPSV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSignature;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSubXCV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlVTS;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessLongTermData;
import eu.europa.esig.dss.detailedreport.jaxb.XmlXCV;
import eu.europa.esig.dss.diagnostic.DiagnosticDataFacade;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCRLDistributionPoints;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificate;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.enumerations.CertificateExtensionEnum;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.ValidationPolicy;
import eu.europa.esig.dss.policy.jaxb.CertificateConstraints;
import eu.europa.esig.dss.policy.jaxb.CertificateValuesConstraint;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.policy.jaxb.MultiValuesConstraint;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.validation.executor.signature.DefaultSignatureProcessExecutor;
import eu.europa.esig.dss.validation.reports.Reports;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RevocationSkipExecutorTest extends AbstractProcessExecutorTest {

    @Test
    void valAssuredSTRevocationSkipTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_st_val_assured.xml"));
        assertNotNull(diagnosticData);

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        CertificateConstraints signingCertificate = validationPolicy.getSignatureConstraints()
                .getBasicSignatureConstraints().getSigningCertificate();

        CertificateValuesConstraint constraint = new CertificateValuesConstraint();
        constraint.setLevel(Level.IGNORE);
        MultiValuesConstraint certExtensionsConstraint = new MultiValuesConstraint();
        certExtensionsConstraint.getId().add("0.4.0.194121.2.1");
        constraint.setCertificateExtensions(certExtensionsConstraint);
        signingCertificate.setRevocationDataSkip(constraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.TOTAL_PASSED, detailedReport.getFinalIndication(detailedReport.getFirstSignatureId()));

        assertEquals(Indication.INDETERMINATE, detailedReport.getBasicValidationIndication(detailedReport.getFirstSignatureId()));
        assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, detailedReport.getBasicValidationSubIndication(detailedReport.getFirstSignatureId()));

        assertEquals(Indication.PASSED, detailedReport.getLongTermValidationIndication(detailedReport.getFirstSignatureId()));

        assertEquals(Indication.PASSED, detailedReport.getArchiveDataValidationIndication(detailedReport.getFirstSignatureId()));

        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertEquals(Indication.INDETERMINATE, signatureBBB.getConclusion().getIndication());
        assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, signatureBBB.getConclusion().getSubIndication());

        XmlXCV xcv = signatureBBB.getXCV();
        assertNotNull(xcv);
        assertEquals(Indication.INDETERMINATE, xcv.getConclusion().getIndication());
        assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, xcv.getConclusion().getSubIndication());

        List<XmlSubXCV> subXCVs = xcv.getSubXCV();
        assertEquals(4, subXCVs.size());

        XmlSubXCV xmlSubXCV = subXCVs.get(0);
        assertEquals(Indication.INDETERMINATE, xmlSubXCV.getConclusion().getIndication());
        assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, xmlSubXCV.getConclusion().getSubIndication());

        boolean revocationSkipCheckFound = false;
        boolean revocationDataPresentCheckFound = false;
        for (XmlConstraint xmlConstraint : xmlSubXCV.getConstraint()) {
            if (MessageTag.BBB_XCV_IRDCSFC.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.IGNORED, xmlConstraint.getStatus());
                revocationSkipCheckFound = true;
            } else if (MessageTag.BBB_XCV_IRDPFC.getId().equals(xmlConstraint.getName().getKey())) {
                revocationDataPresentCheckFound = true;
            }
        }
        assertTrue(revocationSkipCheckFound);
        assertFalse(revocationDataPresentCheckFound);

        for (XmlSubXCV subXCV : subXCVs) {
            if (xmlSubXCV != subXCV) {
                assertEquals(Indication.PASSED, subXCV.getConclusion().getIndication());

                revocationSkipCheckFound = false;
                revocationDataPresentCheckFound = false;
                for (XmlConstraint xmlConstraint : subXCV.getConstraint()) {
                    if (MessageTag.BBB_XCV_IRDCSFC.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.IGNORED, xmlConstraint.getStatus());
                        revocationSkipCheckFound = true;
                    } else if (MessageTag.BBB_XCV_IRDPFC.getId().equals(xmlConstraint.getName().getKey())) {
                        revocationDataPresentCheckFound = true;
                    }
                }
                assertFalse(revocationSkipCheckFound);
                assertTrue(revocationDataPresentCheckFound || subXCV.isTrustAnchor());
            }
        }

        XmlPSV psv = signatureBBB.getPSV();
        assertNull(psv);

        XmlVTS vts = signatureBBB.getVTS();
        assertNull(vts);

        XmlSignature xmlSignature = detailedReport.getXmlSignatureById(detailedReport.getFirstSignatureId());
        assertNotNull(xmlSignature);

        XmlValidationProcessLongTermData validationProcessLongTermData = xmlSignature.getValidationProcessLongTermData();
        assertNotNull(validationProcessLongTermData);

        boolean revocationCheckFound = false;
        for (XmlConstraint xmlConstraint : validationProcessLongTermData.getConstraint()) {
            if (MessageTag.LTV_ISCKNR.getId().equals(xmlConstraint.getName().getKey())) {
                revocationCheckFound = true;
                break;
            }
        }
        assertFalse(revocationCheckFound);

        checkReports(reports);
    }

    @Test
    void noRevAvailRevocationSkipTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_no_rev_avail.xml"));
        assertNotNull(diagnosticData);

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        CertificateConstraints signingCertificate = validationPolicy.getSignatureConstraints()
                .getBasicSignatureConstraints().getSigningCertificate();

        CertificateValuesConstraint constraint = new CertificateValuesConstraint();
        constraint.setLevel(Level.IGNORE);
        MultiValuesConstraint certExtensionsConstraint = new MultiValuesConstraint();
        certExtensionsConstraint.getId().add("2.5.29.56");
        constraint.setCertificateExtensions(certExtensionsConstraint);
        signingCertificate.setRevocationDataSkip(constraint);

        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.FAIL);
        signingCertificate.setNoRevAvail(levelConstraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.TOTAL_PASSED, detailedReport.getFinalIndication(detailedReport.getFirstSignatureId()));

        assertEquals(Indication.INDETERMINATE, detailedReport.getBasicValidationIndication(detailedReport.getFirstSignatureId()));
        assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, detailedReport.getBasicValidationSubIndication(detailedReport.getFirstSignatureId()));

        assertEquals(Indication.PASSED, detailedReport.getLongTermValidationIndication(detailedReport.getFirstSignatureId()));

        assertEquals(Indication.PASSED, detailedReport.getArchiveDataValidationIndication(detailedReport.getFirstSignatureId()));

        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertEquals(Indication.INDETERMINATE, signatureBBB.getConclusion().getIndication());
        assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, signatureBBB.getConclusion().getSubIndication());

        XmlXCV xcv = signatureBBB.getXCV();
        assertNotNull(xcv);
        assertEquals(Indication.INDETERMINATE, xcv.getConclusion().getIndication());
        assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, xcv.getConclusion().getSubIndication());

        List<XmlSubXCV> subXCVs = xcv.getSubXCV();
        assertEquals(4, subXCVs.size());

        XmlSubXCV xmlSubXCV = subXCVs.get(0);
        assertEquals(Indication.INDETERMINATE, xmlSubXCV.getConclusion().getIndication());
        assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, xmlSubXCV.getConclusion().getSubIndication());

        boolean revocationSkipCheckFound = false;
        boolean revocationDataPresentCheckFound = false;
        boolean noRevAvailCheckFound = false;
        for (XmlConstraint xmlConstraint : xmlSubXCV.getConstraint()) {
            if (MessageTag.BBB_XCV_IRDCSFC.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.IGNORED, xmlConstraint.getStatus());
                revocationSkipCheckFound = true;
            } else if (MessageTag.BBB_XCV_IRDPFC.getId().equals(xmlConstraint.getName().getKey())) {
                revocationDataPresentCheckFound = true;
            } else if (MessageTag.BBB_XCV_ICNRAEV.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                noRevAvailCheckFound = true;
            }
        }
        assertTrue(revocationSkipCheckFound);
        assertFalse(revocationDataPresentCheckFound);
        assertTrue(noRevAvailCheckFound);

        for (XmlSubXCV subXCV : subXCVs) {
            if (xmlSubXCV != subXCV) {
                assertEquals(Indication.PASSED, subXCV.getConclusion().getIndication());

                revocationSkipCheckFound = false;
                revocationDataPresentCheckFound = false;
                noRevAvailCheckFound = false;
                for (XmlConstraint xmlConstraint : subXCV.getConstraint()) {
                    if (MessageTag.BBB_XCV_IRDCSFC.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.IGNORED, xmlConstraint.getStatus());
                        revocationSkipCheckFound = true;
                    } else if (MessageTag.BBB_XCV_IRDPFC.getId().equals(xmlConstraint.getName().getKey())) {
                        revocationDataPresentCheckFound = true;
                    } else if (MessageTag.BBB_XCV_ICNRAEV.getId().equals(xmlConstraint.getName().getKey())) {
                        noRevAvailCheckFound = true;
                    }
                }
                assertFalse(revocationSkipCheckFound);
                assertTrue(revocationDataPresentCheckFound || subXCV.isTrustAnchor());
                assertFalse(noRevAvailCheckFound);
            }
        }

        XmlPSV psv = signatureBBB.getPSV();
        assertNull(psv);

        XmlVTS vts = signatureBBB.getVTS();
        assertNull(vts);

        checkReports(reports);
    }

    @Test
    void noRevAvailConformanceFailTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_no_rev_avail.xml"));
        assertNotNull(diagnosticData);

        XmlCertificate xmlCertificate = diagnosticData.getSignatures().get(0).getSigningCertificate().getCertificate();
        XmlCRLDistributionPoints xmlCRLDistributionPoints = new XmlCRLDistributionPoints();
        xmlCRLDistributionPoints.setOID(CertificateExtensionEnum.CRL_DISTRIBUTION_POINTS.getOid());
        xmlCRLDistributionPoints.getCrlUrl().add("http://crl.distribution.point");
        xmlCertificate.getCertificateExtensions().add(xmlCRLDistributionPoints);

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        CertificateConstraints signingCertificate = validationPolicy.getSignatureConstraints()
                .getBasicSignatureConstraints().getSigningCertificate();

        CertificateValuesConstraint constraint = new CertificateValuesConstraint();
        constraint.setLevel(Level.IGNORE);
        MultiValuesConstraint certExtensionsConstraint = new MultiValuesConstraint();
        certExtensionsConstraint.getId().add("2.5.29.56");
        constraint.setCertificateExtensions(certExtensionsConstraint);
        signingCertificate.setRevocationDataSkip(constraint);

        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.FAIL);
        signingCertificate.setNoRevAvail(levelConstraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_XCV_ICNRAEV_ANS)));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.INDETERMINATE, detailedReport.getFinalIndication(detailedReport.getFirstSignatureId()));
        assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, detailedReport.getFinalSubIndication(detailedReport.getFirstSignatureId()));

        assertEquals(Indication.INDETERMINATE, detailedReport.getBasicValidationIndication(detailedReport.getFirstSignatureId()));
        assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, detailedReport.getBasicValidationSubIndication(detailedReport.getFirstSignatureId()));

        assertEquals(Indication.INDETERMINATE, detailedReport.getLongTermValidationIndication(detailedReport.getFirstSignatureId()));
        assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, detailedReport.getLongTermValidationSubIndication(detailedReport.getFirstSignatureId()));

        assertEquals(Indication.INDETERMINATE, detailedReport.getArchiveDataValidationIndication(detailedReport.getFirstSignatureId()));
        assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, detailedReport.getArchiveDataValidationSubIndication(detailedReport.getFirstSignatureId()));

        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertEquals(Indication.INDETERMINATE, signatureBBB.getConclusion().getIndication());
        assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, signatureBBB.getConclusion().getSubIndication());

        XmlXCV xcv = signatureBBB.getXCV();
        assertNotNull(xcv);
        assertEquals(Indication.INDETERMINATE, xcv.getConclusion().getIndication());
        assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, xcv.getConclusion().getSubIndication());

        List<XmlSubXCV> subXCVs = xcv.getSubXCV();
        assertEquals(4, subXCVs.size());

        XmlSubXCV xmlSubXCV = subXCVs.get(0);
        assertEquals(Indication.INDETERMINATE, xmlSubXCV.getConclusion().getIndication());
        assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, xmlSubXCV.getConclusion().getSubIndication());

        boolean revocationSkipCheckFound = false;
        boolean revocationDataPresentCheckFound = false;
        boolean noRevAvailCheckFound = false;
        for (XmlConstraint xmlConstraint : xmlSubXCV.getConstraint()) {
            if (MessageTag.BBB_XCV_IRDCSFC.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.IGNORED, xmlConstraint.getStatus());
                revocationSkipCheckFound = true;
            } else if (MessageTag.BBB_XCV_IRDPFC.getId().equals(xmlConstraint.getName().getKey())) {
                revocationDataPresentCheckFound = true;
            } else if (MessageTag.BBB_XCV_ICNRAEV.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                assertEquals(MessageTag.BBB_XCV_ICNRAEV_ANS.getId(), xmlConstraint.getError().getKey());
                noRevAvailCheckFound = true;
            }
        }
        assertFalse(revocationSkipCheckFound);
        assertFalse(revocationDataPresentCheckFound);
        assertTrue(noRevAvailCheckFound);

        for (XmlSubXCV subXCV : subXCVs) {
            if (xmlSubXCV != subXCV) {
                assertEquals(Indication.PASSED, subXCV.getConclusion().getIndication());

                revocationSkipCheckFound = false;
                revocationDataPresentCheckFound = false;
                noRevAvailCheckFound = false;
                for (XmlConstraint xmlConstraint : subXCV.getConstraint()) {
                    if (MessageTag.BBB_XCV_IRDCSFC.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.IGNORED, xmlConstraint.getStatus());
                        revocationSkipCheckFound = true;
                    } else if (MessageTag.BBB_XCV_IRDPFC.getId().equals(xmlConstraint.getName().getKey())) {
                        revocationDataPresentCheckFound = true;
                    } else if (MessageTag.BBB_XCV_ICNRAEV.getId().equals(xmlConstraint.getName().getKey())) {
                        noRevAvailCheckFound = true;
                    }
                }
                assertFalse(revocationSkipCheckFound);
                assertTrue(revocationDataPresentCheckFound || subXCV.isTrustAnchor());
                assertFalse(noRevAvailCheckFound);
            }
        }

        XmlPSV psv = signatureBBB.getPSV();
        assertNull(psv);

        XmlVTS vts = signatureBBB.getVTS();
        assertNull(vts);

        checkReports(reports);
    }

    @Test
    void certPolicyInformRevocationSkipTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_st_val_assured.xml"));
        assertNotNull(diagnosticData);

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        CertificateConstraints signingCertificate = validationPolicy.getSignatureConstraints()
                .getBasicSignatureConstraints().getSigningCertificate();

        CertificateValuesConstraint constraint = new CertificateValuesConstraint();
        constraint.setLevel(Level.INFORM);
        MultiValuesConstraint certPolicyConstraint = new MultiValuesConstraint();
        certPolicyConstraint.getId().add("1.3.6.2.14");
        constraint.setCertificatePolicies(certPolicyConstraint);
        signingCertificate.setRevocationDataSkip(constraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationInfo(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_XCV_IRDCSFC_ANS)));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.TOTAL_PASSED, detailedReport.getFinalIndication(detailedReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(detailedReport.getAdESValidationInfos(detailedReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.BBB_XCV_IRDCSFC_ANS)));

        assertEquals(Indication.INDETERMINATE, detailedReport.getBasicValidationIndication(detailedReport.getFirstSignatureId()));
        assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, detailedReport.getBasicValidationSubIndication(detailedReport.getFirstSignatureId()));

        assertEquals(Indication.PASSED, detailedReport.getLongTermValidationIndication(detailedReport.getFirstSignatureId()));

        assertEquals(Indication.PASSED, detailedReport.getArchiveDataValidationIndication(detailedReport.getFirstSignatureId()));

        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertEquals(Indication.INDETERMINATE,signatureBBB.getConclusion().getIndication());
        assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, signatureBBB.getConclusion().getSubIndication());
        assertTrue(checkMessageValuePresence(convert(signatureBBB.getConclusion().getInfos()),
                i18nProvider.getMessage(MessageTag.BBB_XCV_IRDCSFC_ANS)));

        XmlXCV xcv = signatureBBB.getXCV();
        assertNotNull(xcv);
        assertEquals(Indication.INDETERMINATE, xcv.getConclusion().getIndication());
        assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, xcv.getConclusion().getSubIndication());
        assertTrue(checkMessageValuePresence(convert(xcv.getConclusion().getInfos()),
                i18nProvider.getMessage(MessageTag.BBB_XCV_IRDCSFC_ANS)));

        List<XmlSubXCV> subXCVs = xcv.getSubXCV();
        assertEquals(4, subXCVs.size());

        XmlSubXCV xmlSubXCV = subXCVs.get(0);
        assertEquals(Indication.INDETERMINATE, xmlSubXCV.getConclusion().getIndication());
        assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, xmlSubXCV.getConclusion().getSubIndication());
        assertTrue(checkMessageValuePresence(convert(xmlSubXCV.getConclusion().getInfos()),
                i18nProvider.getMessage(MessageTag.BBB_XCV_IRDCSFC_ANS)));

        boolean revocationSkipCheckFound = false;
        boolean revocationDataPresentCheckFound = false;
        for (XmlConstraint xmlConstraint : xmlSubXCV.getConstraint()) {
            if (MessageTag.BBB_XCV_IRDCSFC.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.INFORMATION, xmlConstraint.getStatus());
                revocationSkipCheckFound = true;
            } else if (MessageTag.BBB_XCV_IRDPFC.getId().equals(xmlConstraint.getName().getKey())) {
                revocationDataPresentCheckFound = true;
            }
        }
        assertTrue(revocationSkipCheckFound);
        assertFalse(revocationDataPresentCheckFound);

        for (XmlSubXCV subXCV : subXCVs) {
            if (xmlSubXCV != subXCV) {
                assertEquals(Indication.PASSED, subXCV.getConclusion().getIndication());
                assertFalse(checkMessageValuePresence(convert(subXCV.getConclusion().getInfos()),
                        i18nProvider.getMessage(MessageTag.BBB_XCV_IRDCSFC_ANS)));

                revocationSkipCheckFound = false;
                revocationDataPresentCheckFound = false;
                for (XmlConstraint xmlConstraint : subXCV.getConstraint()) {
                    if (MessageTag.BBB_XCV_IRDCSFC.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.INFORMATION, xmlConstraint.getStatus());
                        revocationSkipCheckFound = true;
                    } else if (MessageTag.BBB_XCV_IRDPFC.getId().equals(xmlConstraint.getName().getKey())) {
                        revocationDataPresentCheckFound = true;
                    }
                }
                assertFalse(revocationSkipCheckFound);
                assertTrue(revocationDataPresentCheckFound || subXCV.isTrustAnchor());
            }
        }

        XmlPSV psv = signatureBBB.getPSV();
        assertNull(psv);

        XmlVTS vts = signatureBBB.getVTS();
        assertNull(vts);

        checkReports(reports);
    }

    @Test
    void revocationSkipFailureTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_st_val_assured.xml"));
        assertNotNull(diagnosticData);

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        CertificateConstraints signingCertificate = validationPolicy.getSignatureConstraints()
                .getBasicSignatureConstraints().getSigningCertificate();

        CertificateValuesConstraint constraint = new CertificateValuesConstraint();
        constraint.setLevel(Level.IGNORE);
        MultiValuesConstraint certPolicyConstraint = new MultiValuesConstraint();
        certPolicyConstraint.getId().add("1.2.3.4.5"); // wrong policy OID
        constraint.setCertificatePolicies(certPolicyConstraint);
        signingCertificate.setRevocationDataSkip(constraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.INDETERMINATE, detailedReport.getFinalIndication(detailedReport.getFirstSignatureId()));
        assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, detailedReport.getFinalSubIndication(detailedReport.getFirstSignatureId()));

        assertEquals(Indication.INDETERMINATE, detailedReport.getBasicValidationIndication(detailedReport.getFirstSignatureId()));
        assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, detailedReport.getBasicValidationSubIndication(detailedReport.getFirstSignatureId()));

        assertEquals(Indication.INDETERMINATE, detailedReport.getLongTermValidationIndication(detailedReport.getFirstSignatureId()));
        assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, detailedReport.getLongTermValidationSubIndication(detailedReport.getFirstSignatureId()));

        assertEquals(Indication.INDETERMINATE, detailedReport.getArchiveDataValidationIndication(detailedReport.getFirstSignatureId()));
        assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, detailedReport.getArchiveDataValidationSubIndication(detailedReport.getFirstSignatureId()));

        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertEquals(Indication.INDETERMINATE, signatureBBB.getConclusion().getIndication());
        assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, signatureBBB.getConclusion().getSubIndication());

        XmlXCV xcv = signatureBBB.getXCV();
        assertNotNull(xcv);
        assertEquals(Indication.INDETERMINATE, xcv.getConclusion().getIndication());
        assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, xcv.getConclusion().getSubIndication());

        List<XmlSubXCV> subXCVs = xcv.getSubXCV();
        assertEquals(4, subXCVs.size());

        XmlSubXCV xmlSubXCV = subXCVs.get(0);
        assertEquals(Indication.INDETERMINATE, xmlSubXCV.getConclusion().getIndication());
        assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, xmlSubXCV.getConclusion().getSubIndication());

        boolean revocationSkipCheckFound = false;
        boolean revocationDataPresentCheckFound = false;
        boolean revocationDataAcceptableCheckFound = false;
        for (XmlConstraint xmlConstraint : xmlSubXCV.getConstraint()) {
            if (MessageTag.BBB_XCV_IRDCSFC.getId().equals(xmlConstraint.getName().getKey())) {
                revocationSkipCheckFound = true;
            } else if (MessageTag.BBB_XCV_IRDPFC.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                revocationDataPresentCheckFound = true;
            } else if (MessageTag.BBB_XCV_IARDPFC.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                revocationDataAcceptableCheckFound = true;
            }
        }
        assertFalse(revocationSkipCheckFound);
        assertTrue(revocationDataPresentCheckFound);
        assertTrue(revocationDataAcceptableCheckFound);

        for (XmlSubXCV subXCV : subXCVs) {
            if (xmlSubXCV != subXCV) {
                assertEquals(Indication.PASSED, subXCV.getConclusion().getIndication());

                revocationDataPresentCheckFound = false;
                revocationDataAcceptableCheckFound = false;
                for (XmlConstraint xmlConstraint : subXCV.getConstraint()) {
                    if (MessageTag.BBB_XCV_IRDCSFC.getId().equals(xmlConstraint.getName().getKey())) {
                        revocationSkipCheckFound = true;
                    } else if (MessageTag.BBB_XCV_IRDPFC.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        revocationDataPresentCheckFound = true;
                    } else if (MessageTag.BBB_XCV_IARDPFC.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        revocationDataAcceptableCheckFound = true;
                    }
                }
                assertFalse(revocationSkipCheckFound);
                assertTrue(revocationDataPresentCheckFound || subXCV.isTrustAnchor());
                assertTrue(revocationDataAcceptableCheckFound || subXCV.isTrustAnchor());
            }
        }

        XmlPSV psv = signatureBBB.getPSV();
        assertNull(psv);

        XmlVTS vts = signatureBBB.getVTS();
        assertNull(vts);

        checkReports(reports);
    }

    @Test
    void revocationSkipCertPolicyWrongPlaceTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/diag_data_st_val_assured.xml"));
        assertNotNull(diagnosticData);

        ValidationPolicy validationPolicy = loadDefaultPolicy();
        CertificateConstraints signingCertificate = validationPolicy.getSignatureConstraints()
                .getBasicSignatureConstraints().getSigningCertificate();
        signingCertificate.setRevocationDataSkip(new CertificateValuesConstraint());

        CertificateConstraints revocationConstraints = validationPolicy.getRevocationConstraints()
                .getBasicSignatureConstraints().getSigningCertificate();

        CertificateValuesConstraint constraint = new CertificateValuesConstraint();
        constraint.setLevel(Level.INFORM);
        MultiValuesConstraint certPolicyConstraint = new MultiValuesConstraint();
        certPolicyConstraint.getId().add("1.3.6.2.14");
        constraint.setCertificatePolicies(certPolicyConstraint);
        revocationConstraints.setRevocationDataSkip(constraint);

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(Indication.INDETERMINATE, detailedReport.getFinalIndication(detailedReport.getFirstSignatureId()));
        assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, detailedReport.getFinalSubIndication(detailedReport.getFirstSignatureId()));

        assertEquals(Indication.INDETERMINATE, detailedReport.getBasicValidationIndication(detailedReport.getFirstSignatureId()));
        assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, detailedReport.getBasicValidationSubIndication(detailedReport.getFirstSignatureId()));

        assertEquals(Indication.INDETERMINATE, detailedReport.getLongTermValidationIndication(detailedReport.getFirstSignatureId()));
        assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, detailedReport.getLongTermValidationSubIndication(detailedReport.getFirstSignatureId()));

        assertEquals(Indication.INDETERMINATE, detailedReport.getArchiveDataValidationIndication(detailedReport.getFirstSignatureId()));
        assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, detailedReport.getArchiveDataValidationSubIndication(detailedReport.getFirstSignatureId()));

        XmlBasicBuildingBlocks signatureBBB = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId());
        assertEquals(Indication.INDETERMINATE, signatureBBB.getConclusion().getIndication());
        assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, signatureBBB.getConclusion().getSubIndication());

        XmlXCV xcv = signatureBBB.getXCV();
        assertNotNull(xcv);
        assertEquals(Indication.INDETERMINATE, xcv.getConclusion().getIndication());
        assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, xcv.getConclusion().getSubIndication());

        List<XmlSubXCV> subXCVs = xcv.getSubXCV();
        assertEquals(4, subXCVs.size());

        XmlSubXCV xmlSubXCV = subXCVs.get(0);
        assertEquals(Indication.INDETERMINATE, xmlSubXCV.getConclusion().getIndication());
        assertEquals(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, xmlSubXCV.getConclusion().getSubIndication());

        boolean revocationSkipCheckFound = false;
        boolean revocationDataPresentCheckFound = false;
        boolean revocationDataAcceptableCheckFound = false;
        for (XmlConstraint xmlConstraint : xmlSubXCV.getConstraint()) {
            if (MessageTag.BBB_XCV_IRDCSFC.getId().equals(xmlConstraint.getName().getKey())) {
                revocationSkipCheckFound = true;
            } else if (MessageTag.BBB_XCV_IRDPFC.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                revocationDataPresentCheckFound = true;
            } else if (MessageTag.BBB_XCV_IARDPFC.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                revocationDataAcceptableCheckFound = true;
            }
        }
        assertFalse(revocationSkipCheckFound);
        assertTrue(revocationDataPresentCheckFound);
        assertTrue(revocationDataAcceptableCheckFound);

        for (XmlSubXCV subXCV : subXCVs) {
            if (xmlSubXCV != subXCV) {
                assertEquals(Indication.PASSED, subXCV.getConclusion().getIndication());

                revocationDataPresentCheckFound = false;
                revocationDataAcceptableCheckFound = false;
                for (XmlConstraint xmlConstraint : subXCV.getConstraint()) {
                    if (MessageTag.BBB_XCV_IRDCSFC.getId().equals(xmlConstraint.getName().getKey())) {
                        revocationSkipCheckFound = true;
                    } else if (MessageTag.BBB_XCV_IRDPFC.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        revocationDataPresentCheckFound = true;
                    } else if (MessageTag.BBB_XCV_IARDPFC.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        revocationDataAcceptableCheckFound = true;
                    }
                }
                assertFalse(revocationSkipCheckFound);
                assertTrue(revocationDataPresentCheckFound || subXCV.isTrustAnchor());
                assertTrue(revocationDataAcceptableCheckFound || subXCV.isTrustAnchor());
            }
        }

        XmlPSV psv = signatureBBB.getPSV();
        assertNull(psv);

        XmlVTS vts = signatureBBB.getVTS();
        assertNull(vts);

        checkReports(reports);
    }

}
