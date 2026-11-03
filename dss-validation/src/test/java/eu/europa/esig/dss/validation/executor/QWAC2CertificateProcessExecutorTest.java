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
package eu.europa.esig.dss.validation.executor;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.type.TypeFactory;
import com.fasterxml.jackson.module.jakarta.xmlbind.JakartaXmlBindAnnotationIntrospector;
import eu.europa.esig.dss.detailedreport.DetailedReport;
import eu.europa.esig.dss.detailedreport.DetailedReportFacade;
import eu.europa.esig.dss.detailedreport.jaxb.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.detailedreport.jaxb.XmlCV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlCertificate;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlDetailedReport;
import eu.europa.esig.dss.detailedreport.jaxb.XmlQWACProcess;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSAV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationQWACProcess;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationSignatureQualification;
import eu.europa.esig.dss.diagnostic.DiagnosticDataFacade;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificateExtension;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificatePolicies;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificatePolicy;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificateRef;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificateRevocation;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.diagnostic.jaxb.XmlFoundCertificates;
import eu.europa.esig.dss.diagnostic.jaxb.XmlGeneralName;
import eu.europa.esig.dss.diagnostic.jaxb.XmlOID;
import eu.europa.esig.dss.diagnostic.jaxb.XmlQcStatements;
import eu.europa.esig.dss.diagnostic.jaxb.XmlRelatedCertificate;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignature;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSubjectAlternativeNames;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTLSCertificateBindingSignature;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTrustService;
import eu.europa.esig.dss.enumerations.AdditionalServiceInformation;
import eu.europa.esig.dss.enumerations.CertificateExtensionEnum;
import eu.europa.esig.dss.enumerations.CertificatePolicy;
import eu.europa.esig.dss.enumerations.CertificateQualification;
import eu.europa.esig.dss.enumerations.CertificateRefOrigin;
import eu.europa.esig.dss.enumerations.CertificateStatus;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.enumerations.GeneralNameType;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.JWSSerializationType;
import eu.europa.esig.dss.enumerations.Level;
import eu.europa.esig.dss.enumerations.QCTypeEnum;
import eu.europa.esig.dss.enumerations.QWACProfile;
import eu.europa.esig.dss.enumerations.RevocationReason;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignatureQualification;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.enumerations.ValidationTime;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.EtsiValidationPolicy;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.simplecertificatereport.SimpleCertificateReport;
import eu.europa.esig.dss.simplecertificatereport.SimpleCertificateReportFacade;
import eu.europa.esig.dss.simplecertificatereport.jaxb.XmlSimpleCertificateReport;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.executor.certificate.qwac.QWACCertificateProcessExecutor;
import eu.europa.esig.dss.validation.policy.ValidationPolicyLoader;
import eu.europa.esig.dss.validation.process.ValidationProcessUtils;
import eu.europa.esig.dss.validation.reports.CertificateReports;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.util.Calendar;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

class QWAC2CertificateProcessExecutorTest extends AbstractTestValidationExecutor {

    private static final String QWAC_VALIDATION_POLICY_LOCATION = "/diag-data/policy/qwac-constraint.xml";

    private static I18nProvider i18nProvider;

    @BeforeAll
    static void init() {
        i18nProvider = new I18nProvider(Locale.getDefault());
    }

    @Test
    void validTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/qwac-validation/2-qwac-valid-diag-data.xml"));
        assertNotNull(diagnosticData);

        String certificateId = "C-83D242F9A51C7A62BA1B774268EAAECBAB097479E83D8675C14F02DFB269FE77";

        QWACCertificateProcessExecutor executor = new QWACCertificateProcessExecutor();
        executor.setCertificateId(certificateId);
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        CertificateReports reports = executor.execute();

        SimpleCertificateReport simpleReport = reports.getSimpleReport();
        assertNotNull(simpleReport);

        assertEquals(CertificateQualification.NA, simpleReport.getQualificationAtCertificateIssuance());
        assertTrue(Utils.isCollectionEmpty(simpleReport.getQualificationInfoAtIssuanceTime(certificateId)));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getQualificationWarningsAtIssuanceTime(certificateId)));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getQualificationErrorsAtIssuanceTime(certificateId)));

        assertEquals(CertificateQualification.NA, simpleReport.getQualificationAtValidationTime());
        assertTrue(Utils.isCollectionEmpty(simpleReport.getQualificationInfoAtValidationTime(certificateId)));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getQualificationWarningsAtValidationTime(certificateId)));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getQualificationErrorsAtValidationTime(certificateId)));

        assertEquals(QWACProfile.TLS_BY_QWAC_2, simpleReport.getQWACProfile());

        String bindingSignatureIssuerId = simpleReport.getTLSBindingSignatureIssuerCertificate().getId();
        assertEquals(CertificateQualification.QCERT_FOR_WSA, simpleReport.getTLSBindingSignatureIssuerQualificationAtCertificateIssuance());
        assertTrue(Utils.isCollectionEmpty(simpleReport.getQualificationInfoAtIssuanceTime(bindingSignatureIssuerId)));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getQualificationWarningsAtIssuanceTime(bindingSignatureIssuerId)));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getQualificationErrorsAtIssuanceTime(bindingSignatureIssuerId)));

        assertEquals(CertificateQualification.QCERT_FOR_WSA, simpleReport.getTLSBindingSignatureIssuerQualificationAtValidationTime());
        assertTrue(Utils.isCollectionEmpty(simpleReport.getQualificationInfoAtValidationTime(bindingSignatureIssuerId)));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getQualificationWarningsAtValidationTime(bindingSignatureIssuerId)));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getQualificationErrorsAtValidationTime(bindingSignatureIssuerId)));
        assertEquals(QWACProfile.QWAC_2, simpleReport.getTLSBindingSignatureIssuerCertificateQWACProfile());

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(QWACProfile.TLS_BY_QWAC_2, detailedReport.getCertificateQWACProfile(certificateId));

        XmlCertificate xmlCertificate = detailedReport.getXmlCertificateById(certificateId);
        assertNotNull(xmlCertificate);

        XmlQWACProcess qwacProcess = xmlCertificate.getQWACProcess();
        assertNotNull(qwacProcess);
        assertEquals(certificateId, qwacProcess.getId());
        assertEquals(QWACProfile.TLS_BY_QWAC_2, qwacProcess.getQWACType());
        assertEquals(Indication.PASSED, qwacProcess.getConclusion().getIndication());

        boolean isQWACValidCheckFound = false;
        for (XmlConstraint xmlConstraint : qwacProcess.getConstraint()) {
            if (MessageTag.QWAC_VALID.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                isQWACValidCheckFound = true;
            }
        }
        assertTrue(isQWACValidCheckFound);

        // 1-qwac checks
        boolean is1QWACProcessPresent = false;
        boolean bbbCheckPresent = false;
        boolean qwac1DomainNamePresent = false;
        boolean linkHeaderPresent = false;
        boolean sigFormCheckPresent = false;
        boolean jadesCheckPresent = false;
        boolean jadesCompactCheckPresent = false;
        boolean expTimeCheckPresent = false;
        boolean sigExpCheckPresent = false;
        boolean qwac2CheckPresent = false;
        boolean sigValidCheckPresent = false;
        boolean tlsCertBindingValidCheckPresent = false;

        boolean isTlsSupportedBy2QWACProcessPresent = false;
        for (XmlValidationQWACProcess xmlValidationQWACProcess : qwacProcess.getValidationQWACProcess()) {
            if (i18nProvider.getMessage(MessageTag.QWAC_VALIDATION_PROFILE,
                    ValidationProcessUtils.getQWACValidationMessageTag(QWACProfile.QWAC_1)).equals(xmlValidationQWACProcess.getTitle())) {
                assertEquals(Indication.FAILED, xmlValidationQWACProcess.getConclusion().getIndication());
                is1QWACProcessPresent = true;

            } else if (i18nProvider.getMessage(MessageTag.QWAC_VALIDATION_PROFILE,
                    ValidationProcessUtils.getQWACValidationMessageTag(QWACProfile.TLS_BY_QWAC_2)).equals(xmlValidationQWACProcess.getTitle())) {
                assertEquals(Indication.PASSED, xmlValidationQWACProcess.getConclusion().getIndication());
                for (XmlConstraint xmlConstraint : xmlValidationQWACProcess.getConstraint()) {
                    assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                    if (MessageTag.BBB_ACCEPT.getId().equals(xmlConstraint.getName().getKey())) {
                        bbbCheckPresent = true;
                    } else if (MessageTag.QWAC_DOMAIN_NAME.getId().equals(xmlConstraint.getName().getKey())) {
                        qwac1DomainNamePresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_URL.getId().equals(xmlConstraint.getName().getKey())) {
                        linkHeaderPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG.getId().equals(xmlConstraint.getName().getKey())) {
                        sigFormCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG_FORM.getId().equals(xmlConstraint.getName().getKey())) {
                        jadesCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG_SER.getId().equals(xmlConstraint.getName().getKey())) {
                        jadesCompactCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG_EXP.getId().equals(xmlConstraint.getName().getKey())) {
                        expTimeCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG_EXPIRY_DATE.getId().equals(xmlConstraint.getName().getKey())) {
                        sigExpCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_QWAC2.getId().equals(xmlConstraint.getName().getKey())) {
                        qwac2CheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG_VALID.getId().equals(xmlConstraint.getName().getKey())) {
                        sigValidCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_CERT_IDENTIFIED.getId().equals(xmlConstraint.getName().getKey())) {
                        tlsCertBindingValidCheckPresent = true;
                    }
                }

                isTlsSupportedBy2QWACProcessPresent = true;
            }
        }
        assertTrue(is1QWACProcessPresent);
        assertTrue(bbbCheckPresent);
        assertTrue(qwac1DomainNamePresent);
        assertTrue(linkHeaderPresent);
        assertTrue(sigFormCheckPresent);
        assertTrue(jadesCheckPresent);
        assertTrue(jadesCompactCheckPresent);
        assertTrue(expTimeCheckPresent);
        assertTrue(sigExpCheckPresent);
        assertTrue(qwac2CheckPresent);
        assertTrue(sigValidCheckPresent);
        assertTrue(tlsCertBindingValidCheckPresent);
        assertTrue(isTlsSupportedBy2QWACProcessPresent);

        XmlSignature tlsCertificateBindingSignature = diagnosticData
                .getConnectionInfo().getTLSCertificateBindingSignature().getSignature();

        XmlBasicBuildingBlocks sigBBB = detailedReport.getBasicBuildingBlockById(tlsCertificateBindingSignature.getId());
        assertNotNull(sigBBB);
        assertEquals(Indication.PASSED, sigBBB.getConclusion().getIndication());

        XmlSAV xmlSAV = sigBBB.getSAV();
        assertNotNull(xmlSAV);
        assertEquals(Indication.PASSED, xmlSAV.getConclusion().getIndication());

        boolean signCertCheckPresent = false;
        boolean signCertOnlyOneCheckPresent = false;
        boolean kidCheckPresent = false;
        boolean signTimeCheckPresent = false;
        boolean ctyCheckPresent = false;
        for (XmlConstraint xmlConstraint : xmlSAV.getConstraint()) {
            assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
            if (MessageTag.BBB_ICS_ISASCP.getId().equals(xmlConstraint.getName().getKey())) {
                signCertCheckPresent = true;
            } else if (MessageTag.BBB_ICS_ISASCPU.getId().equals(xmlConstraint.getName().getKey())) {
                signCertOnlyOneCheckPresent = true;
            } else if (MessageTag.BBB_ICS_ISAKIDP.getId().equals(xmlConstraint.getName().getKey())) {
                kidCheckPresent = true;
            } else if (MessageTag.BBB_SAV_ISQPSTP.getId().equals(xmlConstraint.getName().getKey())) {
                signTimeCheckPresent = true;
            } else if (MessageTag.BBB_SAV_ISQPCTP.getId().equals(xmlConstraint.getName().getKey())) {
                ctyCheckPresent = true;
            }
        }
        assertTrue(signCertCheckPresent);
        assertTrue(signCertOnlyOneCheckPresent);
        assertTrue(kidCheckPresent);
        assertTrue(signTimeCheckPresent);
        assertTrue(ctyCheckPresent);

        eu.europa.esig.dss.diagnostic.jaxb.XmlCertificate signingCertificate =
                tlsCertificateBindingSignature.getSigningCertificate().getCertificate();
        assertEquals(QWACProfile.QWAC_2, detailedReport.getCertificateQWACProfile(signingCertificate.getId()));

        eu.europa.esig.dss.detailedreport.jaxb.XmlSignature xmlSignature = detailedReport.getXmlSignatureById(tlsCertificateBindingSignature.getId());
        assertEquals(Indication.TOTAL_PASSED, xmlSignature.getConclusion().getIndication());

        XmlValidationSignatureQualification signatureQualification = xmlSignature.getValidationSignatureQualification();
        assertEquals(SignatureQualification.NOT_ADES, signatureQualification.getSignatureQualification());

        XmlQWACProcess signatureQWACProcess = signatureQualification.getQWACProcess();
        assertEquals(signingCertificate.getId(), signatureQWACProcess.getId());
        assertEquals(QWACProfile.QWAC_2, signatureQWACProcess.getQWACType());
        assertEquals(Indication.PASSED, signatureQWACProcess.getConclusion().getIndication());

        // 2-qwac checks
        boolean certPolicyCheckPresent = false;
        boolean certQualConclusiveCheckPresent = false;
        boolean wsaCheckAtIssuanceTimePresent = false;
        boolean wsaCheckAtValidationTimePresent = false;
        boolean certValidityPeriodCheckPresent = false;
        boolean domainNamePresent = false;
        boolean extKeyUsageCheckPresent = false;
        boolean bbbCheckConclusive = false;
        boolean is2QWACProcessPresent = false;
        for (XmlValidationQWACProcess xmlValidationQWACProcess : signatureQWACProcess.getValidationQWACProcess()) {
            if (i18nProvider.getMessage(MessageTag.QWAC_VALIDATION_PROFILE,
                    ValidationProcessUtils.getQWACValidationMessageTag(QWACProfile.QWAC_2)).equals(xmlValidationQWACProcess.getTitle())) {
                assertEquals(Indication.PASSED, xmlValidationQWACProcess.getConclusion().getIndication());
                for (XmlConstraint xmlConstraint : xmlValidationQWACProcess.getConstraint()) {
                    assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                    if (MessageTag.QWAC_CERT_POLICY.getId().equals(xmlConstraint.getName().getKey())) {
                        certPolicyCheckPresent = true;
                    } else if (MessageTag.QWAC_CERT_QUAL_CONCLUSIVE.getId().equals(xmlConstraint.getName().getKey())) {
                        certQualConclusiveCheckPresent = true;
                    } else if (MessageTag.QWAC_IS_WSA_AT_TIME.getId().equals(xmlConstraint.getName().getKey())) {
                        if (i18nProvider.getMessage(MessageTag.QWAC_IS_WSA_AT_TIME, ValidationProcessUtils.getValidationTimeMessageTag(
                                ValidationTime.CERTIFICATE_ISSUANCE_TIME)).equals(xmlConstraint.getName().getValue())) {
                            wsaCheckAtIssuanceTimePresent = true;
                        } else if (i18nProvider.getMessage(MessageTag.QWAC_IS_WSA_AT_TIME, ValidationProcessUtils.getValidationTimeMessageTag(
                                ValidationTime.VALIDATION_TIME)).equals(xmlConstraint.getName().getValue())) {
                            wsaCheckAtValidationTimePresent = true;
                        }
                    } else if (MessageTag.QWAC_VAL_PERIOD.getId().equals(xmlConstraint.getName().getKey())) {
                        certValidityPeriodCheckPresent = true;
                    } else if (MessageTag.QWAC_DOMAIN_NAME.getId().equals(xmlConstraint.getName().getKey())) {
                        domainNamePresent = true;
                    } else if (MessageTag.QWAC2_EXT_KEY_USAGE.getId().equals(xmlConstraint.getName().getKey())) {
                        extKeyUsageCheckPresent = true;
                    } else if (MessageTag.BBB_ACCEPT.getId().equals(xmlConstraint.getName().getKey())) {
                        bbbCheckConclusive = true;
                    }
                }

                is2QWACProcessPresent = true;
            }
        }
        assertTrue(certPolicyCheckPresent);
        assertTrue(certQualConclusiveCheckPresent);
        assertTrue(wsaCheckAtIssuanceTimePresent);
        assertTrue(wsaCheckAtValidationTimePresent);
        assertTrue(certValidityPeriodCheckPresent);
        assertTrue(domainNamePresent);
        assertTrue(extKeyUsageCheckPresent);
        assertTrue(bbbCheckConclusive);
        assertTrue(is2QWACProcessPresent);

        checkReports(reports);
    }

    @Test
    void noTLTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/qwac-validation/2-qwac-no-tl-diag-data.xml"));
        assertNotNull(diagnosticData);

        String certificateId = "C-83D242F9A51C7A62BA1B774268EAAECBAB097479E83D8675C14F02DFB269FE77";

        QWACCertificateProcessExecutor executor = new QWACCertificateProcessExecutor();
        executor.setCertificateId(certificateId);
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        CertificateReports reports = executor.execute();

        SimpleCertificateReport simpleReport = reports.getSimpleReport();
        assertNotNull(simpleReport);

        assertEquals(QWACProfile.NOT_QWAC, simpleReport.getQWACProfile());
        assertEquals(QWACProfile.NOT_QWAC, simpleReport.getTLSBindingSignatureIssuerCertificateQWACProfile());

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(QWACProfile.NOT_QWAC, detailedReport.getCertificateQWACProfile(certificateId));

        XmlCertificate xmlCertificate = detailedReport.getXmlCertificateById(certificateId);
        assertNotNull(xmlCertificate);

        XmlQWACProcess qwacProcess = xmlCertificate.getQWACProcess();
        assertNotNull(qwacProcess);
        assertEquals(certificateId, qwacProcess.getId());
        assertEquals(QWACProfile.NOT_QWAC, qwacProcess.getQWACType());
        assertEquals(Indication.FAILED, qwacProcess.getConclusion().getIndication());

        boolean isQWACValidCheckFound = false;
        for (XmlConstraint xmlConstraint : qwacProcess.getConstraint()) {
            if (MessageTag.QWAC_VALID.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                assertEquals(MessageTag.QWAC_VALID_ANS.getId(), xmlConstraint.getError().getKey());
                isQWACValidCheckFound = true;
            }
        }
        assertTrue(isQWACValidCheckFound);

        // 1-qwac checks
        boolean is1QWACProcessPresent = false;
        boolean bbbCheckPresent = false;
        boolean qwac1DomainNamePresent = false;
        boolean linkHeaderPresent = false;
        boolean sigFormCheckPresent = false;
        boolean jadesCheckPresent = false;
        boolean jadesCompactCheckPresent = false;
        boolean expTimeCheckPresent = false;
        boolean sigExpCheckPresent = false;
        boolean qwac2CheckPresent = false;
        boolean sigValidCheckPresent = false;
        boolean tlsCertBindingValidCheckPresent = false;

        boolean isTlsSupportedBy2QWACProcessPresent = false;
        for (XmlValidationQWACProcess xmlValidationQWACProcess : qwacProcess.getValidationQWACProcess()) {
            if (i18nProvider.getMessage(MessageTag.QWAC_VALIDATION_PROFILE,
                    ValidationProcessUtils.getQWACValidationMessageTag(QWACProfile.QWAC_1)).equals(xmlValidationQWACProcess.getTitle())) {
                assertEquals(Indication.FAILED, xmlValidationQWACProcess.getConclusion().getIndication());
                is1QWACProcessPresent = true;

            } else if (i18nProvider.getMessage(MessageTag.QWAC_VALIDATION_PROFILE,
                    ValidationProcessUtils.getQWACValidationMessageTag(QWACProfile.TLS_BY_QWAC_2)).equals(xmlValidationQWACProcess.getTitle())) {
                assertEquals(Indication.FAILED, xmlValidationQWACProcess.getConclusion().getIndication());
                for (XmlConstraint xmlConstraint : xmlValidationQWACProcess.getConstraint()) {
                    if (MessageTag.BBB_ACCEPT.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        bbbCheckPresent = true;
                    } else if (MessageTag.QWAC_DOMAIN_NAME.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        qwac1DomainNamePresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_URL.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        linkHeaderPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        sigFormCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG_FORM.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        jadesCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG_SER.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        jadesCompactCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG_EXP.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        expTimeCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG_EXPIRY_DATE.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        sigExpCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_QWAC2.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                        assertEquals(MessageTag.TLS_CERT_BINDING_QWAC2_ANS.getId(), xmlConstraint.getError().getKey());
                        qwac2CheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG_VALID.getId().equals(xmlConstraint.getName().getKey())) {
                        sigValidCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_CERT_IDENTIFIED.getId().equals(xmlConstraint.getName().getKey())) {
                        tlsCertBindingValidCheckPresent = true;
                    }
                }

                isTlsSupportedBy2QWACProcessPresent = true;
            }
        }
        assertTrue(is1QWACProcessPresent);
        assertTrue(bbbCheckPresent);
        assertTrue(qwac1DomainNamePresent);
        assertTrue(linkHeaderPresent);
        assertTrue(sigFormCheckPresent);
        assertTrue(jadesCheckPresent);
        assertTrue(jadesCompactCheckPresent);
        assertTrue(expTimeCheckPresent);
        assertTrue(sigExpCheckPresent);
        assertTrue(qwac2CheckPresent);
        assertFalse(sigValidCheckPresent);
        assertFalse(tlsCertBindingValidCheckPresent);
        assertTrue(isTlsSupportedBy2QWACProcessPresent);

        XmlSignature tlsCertificateBindingSignature = diagnosticData
                .getConnectionInfo().getTLSCertificateBindingSignature().getSignature();

        XmlBasicBuildingBlocks sigBBB = detailedReport.getBasicBuildingBlockById(tlsCertificateBindingSignature.getId());
        assertNotNull(sigBBB);
        assertEquals(Indication.PASSED, sigBBB.getConclusion().getIndication());

        XmlSAV xmlSAV = sigBBB.getSAV();
        assertNotNull(xmlSAV);
        assertEquals(Indication.PASSED, xmlSAV.getConclusion().getIndication());

        boolean signCertCheckPresent = false;
        boolean signCertOnlyOneCheckPresent = false;
        boolean kidCheckPresent = false;
        boolean signTimeCheckPresent = false;
        boolean ctyCheckPresent = false;
        for (XmlConstraint xmlConstraint : xmlSAV.getConstraint()) {
            assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
            if (MessageTag.BBB_ICS_ISASCP.getId().equals(xmlConstraint.getName().getKey())) {
                signCertCheckPresent = true;
            } else if (MessageTag.BBB_ICS_ISASCPU.getId().equals(xmlConstraint.getName().getKey())) {
                signCertOnlyOneCheckPresent = true;
            } else if (MessageTag.BBB_ICS_ISAKIDP.getId().equals(xmlConstraint.getName().getKey())) {
                kidCheckPresent = true;
            } else if (MessageTag.BBB_SAV_ISQPSTP.getId().equals(xmlConstraint.getName().getKey())) {
                signTimeCheckPresent = true;
            } else if (MessageTag.BBB_SAV_ISQPCTP.getId().equals(xmlConstraint.getName().getKey())) {
                ctyCheckPresent = true;
            }
        }
        assertTrue(signCertCheckPresent);
        assertTrue(signCertOnlyOneCheckPresent);
        assertTrue(kidCheckPresent);
        assertTrue(signTimeCheckPresent);
        assertTrue(ctyCheckPresent);

        eu.europa.esig.dss.diagnostic.jaxb.XmlCertificate signingCertificate =
                tlsCertificateBindingSignature.getSigningCertificate().getCertificate();
        assertEquals(QWACProfile.NOT_QWAC, detailedReport.getCertificateQWACProfile(signingCertificate.getId()));

        eu.europa.esig.dss.detailedreport.jaxb.XmlSignature xmlSignature = detailedReport.getXmlSignatureById(tlsCertificateBindingSignature.getId());
        assertEquals(Indication.TOTAL_PASSED, xmlSignature.getConclusion().getIndication());

        XmlValidationSignatureQualification signatureQualification = xmlSignature.getValidationSignatureQualification();
        assertEquals(SignatureQualification.NA, signatureQualification.getSignatureQualification());

        XmlQWACProcess signatureQWACProcess = signatureQualification.getQWACProcess();
        assertEquals(signingCertificate.getId(), signatureQWACProcess.getId());
        assertEquals(QWACProfile.NOT_QWAC, signatureQWACProcess.getQWACType());
        assertEquals(Indication.FAILED, signatureQWACProcess.getConclusion().getIndication());

        // 2-qwac checks
        boolean certPolicyCheckPresent = false;
        boolean certQualConclusiveCheckPresent = false;
        boolean wsaCheckAtIssuanceTimePresent = false;
        boolean wsaCheckAtValidationTimePresent = false;
        boolean certValidityPeriodCheckPresent = false;
        boolean domainNamePresent = false;
        boolean extKeyUsageCheckPresent = false;
        boolean bbbCheckConclusive = false;
        boolean is2QWACProcessPresent = false;
        for (XmlValidationQWACProcess xmlValidationQWACProcess : signatureQWACProcess.getValidationQWACProcess()) {
            if (i18nProvider.getMessage(MessageTag.QWAC_VALIDATION_PROFILE,
                    ValidationProcessUtils.getQWACValidationMessageTag(QWACProfile.QWAC_2)).equals(xmlValidationQWACProcess.getTitle())) {
                assertEquals(Indication.FAILED, xmlValidationQWACProcess.getConclusion().getIndication());
                for (XmlConstraint xmlConstraint : xmlValidationQWACProcess.getConstraint()) {
                    if (MessageTag.QWAC_CERT_POLICY.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        certPolicyCheckPresent = true;
                    } else if (MessageTag.QWAC_CERT_QUAL_CONCLUSIVE.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                        assertEquals(MessageTag.QWAC_CERT_QUAL_CONCLUSIVE_ANS.getId(), xmlConstraint.getError().getKey());
                        certQualConclusiveCheckPresent = true;
                    } else if (MessageTag.QWAC_IS_WSA_AT_TIME.getId().equals(xmlConstraint.getName().getKey())) {
                        if (i18nProvider.getMessage(MessageTag.QWAC_IS_WSA_AT_TIME, ValidationProcessUtils.getValidationTimeMessageTag(
                                ValidationTime.CERTIFICATE_ISSUANCE_TIME)).equals(xmlConstraint.getName().getValue())) {
                            wsaCheckAtIssuanceTimePresent = true;
                        } else if (i18nProvider.getMessage(MessageTag.QWAC_IS_WSA_AT_TIME, ValidationProcessUtils.getValidationTimeMessageTag(
                                ValidationTime.VALIDATION_TIME)).equals(xmlConstraint.getName().getValue())) {
                            wsaCheckAtValidationTimePresent = true;
                        }
                    } else if (MessageTag.QWAC_VAL_PERIOD.getId().equals(xmlConstraint.getName().getKey())) {
                        certValidityPeriodCheckPresent = true;
                    } else if (MessageTag.QWAC_DOMAIN_NAME.getId().equals(xmlConstraint.getName().getKey())) {
                        domainNamePresent = true;
                    } else if (MessageTag.QWAC2_EXT_KEY_USAGE.getId().equals(xmlConstraint.getName().getKey())) {
                        extKeyUsageCheckPresent = true;
                    } else if (MessageTag.BBB_ACCEPT.getId().equals(xmlConstraint.getName().getKey())) {
                        bbbCheckConclusive = true;
                    }
                }

                is2QWACProcessPresent = true;
            }
        }
        assertTrue(certPolicyCheckPresent);
        assertTrue(certQualConclusiveCheckPresent);
        assertFalse(wsaCheckAtIssuanceTimePresent);
        assertFalse(wsaCheckAtValidationTimePresent);
        assertFalse(certValidityPeriodCheckPresent);
        assertFalse(domainNamePresent);
        assertFalse(extKeyUsageCheckPresent);
        assertFalse(bbbCheckConclusive);
        assertTrue(is2QWACProcessPresent);

        checkReports(reports);
    }

    @Test
    void qwac2DiffPolicyTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/qwac-validation/2-qwac-valid-diag-data.xml"));
        assertNotNull(diagnosticData);

        XmlTLSCertificateBindingSignature bindingSignature = diagnosticData.getConnectionInfo().getTLSCertificateBindingSignature();

        eu.europa.esig.dss.diagnostic.jaxb.XmlCertificate certificate = bindingSignature.getSignature().getSigningCertificate().getCertificate();
        for (XmlCertificateExtension certificateExtension : certificate.getCertificateExtensions()) {
            if (CertificateExtensionEnum.CERTIFICATE_POLICIES.getOid().equals(certificateExtension.getOID())) {
                XmlCertificatePolicies xmlCertificatePolicies = (XmlCertificatePolicies) certificateExtension;
                XmlCertificatePolicy xmlCertificatePolicy = new XmlCertificatePolicy();
                xmlCertificatePolicy.setValue(CertificatePolicy.QNCP_WEB.getOid());
                xmlCertificatePolicies.getCertificatePolicy().clear();
                xmlCertificatePolicies.getCertificatePolicy().add(xmlCertificatePolicy);
            }
        }

        String certificateId = "C-83D242F9A51C7A62BA1B774268EAAECBAB097479E83D8675C14F02DFB269FE77";

        QWACCertificateProcessExecutor executor = new QWACCertificateProcessExecutor();
        executor.setCertificateId(certificateId);
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        CertificateReports reports = executor.execute();

        SimpleCertificateReport simpleReport = reports.getSimpleReport();
        assertNotNull(simpleReport);

        assertEquals(QWACProfile.NOT_QWAC, simpleReport.getQWACProfile());
        assertEquals(QWACProfile.NOT_QWAC, simpleReport.getTLSBindingSignatureIssuerCertificateQWACProfile());

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(QWACProfile.NOT_QWAC, detailedReport.getCertificateQWACProfile(certificateId));

        XmlCertificate xmlCertificate = detailedReport.getXmlCertificateById(certificateId);
        assertNotNull(xmlCertificate);

        XmlQWACProcess qwacProcess = xmlCertificate.getQWACProcess();
        assertNotNull(qwacProcess);
        assertEquals(certificateId, qwacProcess.getId());
        assertEquals(QWACProfile.NOT_QWAC, qwacProcess.getQWACType());
        assertEquals(Indication.FAILED, qwacProcess.getConclusion().getIndication());

        boolean isQWACValidCheckFound = false;
        for (XmlConstraint xmlConstraint : qwacProcess.getConstraint()) {
            if (MessageTag.QWAC_VALID.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                assertEquals(MessageTag.QWAC_VALID_ANS.getId(), xmlConstraint.getError().getKey());
                isQWACValidCheckFound = true;
            }
        }
        assertTrue(isQWACValidCheckFound);

        // 1-qwac checks
        boolean is1QWACProcessPresent = false;
        boolean bbbCheckPresent = false;
        boolean qwac1DomainNamePresent = false;
        boolean linkHeaderPresent = false;
        boolean sigFormCheckPresent = false;
        boolean jadesCheckPresent = false;
        boolean jadesCompactCheckPresent = false;
        boolean expTimeCheckPresent = false;
        boolean sigExpCheckPresent = false;
        boolean qwac2CheckPresent = false;
        boolean sigValidCheckPresent = false;
        boolean tlsCertBindingValidCheckPresent = false;

        boolean isTlsSupportedBy2QWACProcessPresent = false;
        for (XmlValidationQWACProcess xmlValidationQWACProcess : qwacProcess.getValidationQWACProcess()) {
            if (i18nProvider.getMessage(MessageTag.QWAC_VALIDATION_PROFILE,
                    ValidationProcessUtils.getQWACValidationMessageTag(QWACProfile.QWAC_1)).equals(xmlValidationQWACProcess.getTitle())) {
                assertEquals(Indication.FAILED, xmlValidationQWACProcess.getConclusion().getIndication());
                is1QWACProcessPresent = true;

            } else if (i18nProvider.getMessage(MessageTag.QWAC_VALIDATION_PROFILE,
                    ValidationProcessUtils.getQWACValidationMessageTag(QWACProfile.TLS_BY_QWAC_2)).equals(xmlValidationQWACProcess.getTitle())) {
                assertEquals(Indication.FAILED, xmlValidationQWACProcess.getConclusion().getIndication());
                for (XmlConstraint xmlConstraint : xmlValidationQWACProcess.getConstraint()) {
                    if (MessageTag.BBB_ACCEPT.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        bbbCheckPresent = true;
                    } else if (MessageTag.QWAC_DOMAIN_NAME.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        qwac1DomainNamePresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_URL.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        linkHeaderPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        sigFormCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG_FORM.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        jadesCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG_SER.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        jadesCompactCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG_EXP.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        expTimeCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG_EXPIRY_DATE.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        sigExpCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_QWAC2.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                        assertEquals(MessageTag.TLS_CERT_BINDING_QWAC2_ANS.getId(), xmlConstraint.getError().getKey());
                        qwac2CheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG_VALID.getId().equals(xmlConstraint.getName().getKey())) {
                        sigValidCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_CERT_IDENTIFIED.getId().equals(xmlConstraint.getName().getKey())) {
                        tlsCertBindingValidCheckPresent = true;
                    }
                }

                isTlsSupportedBy2QWACProcessPresent = true;
            }
        }
        assertTrue(is1QWACProcessPresent);
        assertTrue(bbbCheckPresent);
        assertTrue(qwac1DomainNamePresent);
        assertTrue(linkHeaderPresent);
        assertTrue(sigFormCheckPresent);
        assertTrue(jadesCheckPresent);
        assertTrue(jadesCompactCheckPresent);
        assertTrue(expTimeCheckPresent);
        assertTrue(sigExpCheckPresent);
        assertTrue(qwac2CheckPresent);
        assertFalse(sigValidCheckPresent);
        assertFalse(tlsCertBindingValidCheckPresent);
        assertTrue(isTlsSupportedBy2QWACProcessPresent);

        XmlSignature tlsCertificateBindingSignature = diagnosticData
                .getConnectionInfo().getTLSCertificateBindingSignature().getSignature();

        XmlBasicBuildingBlocks sigBBB = detailedReport.getBasicBuildingBlockById(tlsCertificateBindingSignature.getId());
        assertNotNull(sigBBB);
        assertEquals(Indication.PASSED, sigBBB.getConclusion().getIndication());

        XmlSAV xmlSAV = sigBBB.getSAV();
        assertNotNull(xmlSAV);
        assertEquals(Indication.PASSED, xmlSAV.getConclusion().getIndication());

        boolean signCertCheckPresent = false;
        boolean signCertOnlyOneCheckPresent = false;
        boolean kidCheckPresent = false;
        boolean signTimeCheckPresent = false;
        boolean ctyCheckPresent = false;
        for (XmlConstraint xmlConstraint : xmlSAV.getConstraint()) {
            assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
            if (MessageTag.BBB_ICS_ISASCP.getId().equals(xmlConstraint.getName().getKey())) {
                signCertCheckPresent = true;
            } else if (MessageTag.BBB_ICS_ISASCPU.getId().equals(xmlConstraint.getName().getKey())) {
                signCertOnlyOneCheckPresent = true;
            } else if (MessageTag.BBB_ICS_ISAKIDP.getId().equals(xmlConstraint.getName().getKey())) {
                kidCheckPresent = true;
            } else if (MessageTag.BBB_SAV_ISQPSTP.getId().equals(xmlConstraint.getName().getKey())) {
                signTimeCheckPresent = true;
            } else if (MessageTag.BBB_SAV_ISQPCTP.getId().equals(xmlConstraint.getName().getKey())) {
                ctyCheckPresent = true;
            }
        }
        assertTrue(signCertCheckPresent);
        assertTrue(signCertOnlyOneCheckPresent);
        assertTrue(kidCheckPresent);
        assertTrue(signTimeCheckPresent);
        assertTrue(ctyCheckPresent);

        eu.europa.esig.dss.diagnostic.jaxb.XmlCertificate signingCertificate =
                tlsCertificateBindingSignature.getSigningCertificate().getCertificate();
        assertEquals(QWACProfile.NOT_QWAC, detailedReport.getCertificateQWACProfile(signingCertificate.getId()));

        eu.europa.esig.dss.detailedreport.jaxb.XmlSignature xmlSignature = detailedReport.getXmlSignatureById(tlsCertificateBindingSignature.getId());
        assertEquals(Indication.TOTAL_PASSED, xmlSignature.getConclusion().getIndication());

        XmlValidationSignatureQualification signatureQualification = xmlSignature.getValidationSignatureQualification();
        assertEquals(SignatureQualification.NOT_ADES, signatureQualification.getSignatureQualification());

        XmlQWACProcess signatureQWACProcess = signatureQualification.getQWACProcess();
        assertEquals(signingCertificate.getId(), signatureQWACProcess.getId());
        assertEquals(QWACProfile.NOT_QWAC, signatureQWACProcess.getQWACType());
        assertEquals(Indication.FAILED, signatureQWACProcess.getConclusion().getIndication());

        // 2-qwac checks
        boolean certPolicyCheckPresent = false;
        boolean certQualConclusiveCheckPresent = false;
        boolean wsaCheckAtIssuanceTimePresent = false;
        boolean wsaCheckAtValidationTimePresent = false;
        boolean certValidityPeriodCheckPresent = false;
        boolean domainNamePresent = false;
        boolean extKeyUsageCheckPresent = false;
        boolean bbbCheckConclusive = false;
        boolean is2QWACProcessPresent = false;
        for (XmlValidationQWACProcess xmlValidationQWACProcess : signatureQWACProcess.getValidationQWACProcess()) {
            if (i18nProvider.getMessage(MessageTag.QWAC_VALIDATION_PROFILE,
                    ValidationProcessUtils.getQWACValidationMessageTag(QWACProfile.QWAC_2)).equals(xmlValidationQWACProcess.getTitle())) {
                assertEquals(Indication.FAILED, xmlValidationQWACProcess.getConclusion().getIndication());
                for (XmlConstraint xmlConstraint : xmlValidationQWACProcess.getConstraint()) {
                    if (MessageTag.QWAC_CERT_POLICY.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                        assertEquals(MessageTag.QWAC_CERT_POLICY_ANS.getId(), xmlConstraint.getError().getKey());
                        certPolicyCheckPresent = true;
                    } else if (MessageTag.QWAC_CERT_QUAL_CONCLUSIVE.getId().equals(xmlConstraint.getName().getKey())) {
                        certQualConclusiveCheckPresent = true;
                    } else if (MessageTag.QWAC_IS_WSA_AT_TIME.getId().equals(xmlConstraint.getName().getKey())) {
                        if (i18nProvider.getMessage(MessageTag.QWAC_IS_WSA_AT_TIME, ValidationProcessUtils.getValidationTimeMessageTag(
                                ValidationTime.CERTIFICATE_ISSUANCE_TIME)).equals(xmlConstraint.getName().getValue())) {
                            wsaCheckAtIssuanceTimePresent = true;
                        } else if (i18nProvider.getMessage(MessageTag.QWAC_IS_WSA_AT_TIME, ValidationProcessUtils.getValidationTimeMessageTag(
                                ValidationTime.VALIDATION_TIME)).equals(xmlConstraint.getName().getValue())) {
                            wsaCheckAtValidationTimePresent = true;
                        }
                    } else if (MessageTag.QWAC_VAL_PERIOD.getId().equals(xmlConstraint.getName().getKey())) {
                        certValidityPeriodCheckPresent = true;
                    } else if (MessageTag.QWAC_DOMAIN_NAME.getId().equals(xmlConstraint.getName().getKey())) {
                        domainNamePresent = true;
                    } else if (MessageTag.QWAC2_EXT_KEY_USAGE.getId().equals(xmlConstraint.getName().getKey())) {
                        extKeyUsageCheckPresent = true;
                    } else if (MessageTag.BBB_ACCEPT.getId().equals(xmlConstraint.getName().getKey())) {
                        bbbCheckConclusive = true;
                    }
                }

                is2QWACProcessPresent = true;
            }
        }
        assertTrue(certPolicyCheckPresent);
        assertFalse(certQualConclusiveCheckPresent);
        assertFalse(wsaCheckAtIssuanceTimePresent);
        assertFalse(wsaCheckAtValidationTimePresent);
        assertFalse(certValidityPeriodCheckPresent);
        assertFalse(domainNamePresent);
        assertFalse(extKeyUsageCheckPresent);
        assertFalse(bbbCheckConclusive);
        assertTrue(is2QWACProcessPresent);

        checkReports(reports);
    }

    @Test
    void qwac2CertForESigTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/qwac-validation/2-qwac-valid-diag-data.xml"));
        assertNotNull(diagnosticData);

        XmlTLSCertificateBindingSignature bindingSignature = diagnosticData.getConnectionInfo().getTLSCertificateBindingSignature();

        eu.europa.esig.dss.diagnostic.jaxb.XmlCertificate certificate = bindingSignature.getSignature().getSigningCertificate().getCertificate();
        for (XmlCertificateExtension certificateExtension : certificate.getCertificateExtensions()) {
            if (CertificateExtensionEnum.QC_STATEMENTS.getOid().equals(certificateExtension.getOID())) {
                XmlQcStatements xmlQcStatements = (XmlQcStatements) certificateExtension;
                XmlOID xmlOID = new XmlOID();
                xmlOID.setValue(QCTypeEnum.QCT_ESIGN.getOid());
                xmlQcStatements.getQcTypes().clear();
                xmlQcStatements.getQcTypes().add(xmlOID);
            }
        }
        XmlTrustService xmlTrustService = certificate.getTrustServiceProviders().get(0).getTrustServices().get(0);
        xmlTrustService.getAdditionalServiceInfoUris().clear();
        xmlTrustService.getAdditionalServiceInfoUris().add(AdditionalServiceInformation.FOR_ESIGNATURES.getUri());

        String certificateId = "C-83D242F9A51C7A62BA1B774268EAAECBAB097479E83D8675C14F02DFB269FE77";

        QWACCertificateProcessExecutor executor = new QWACCertificateProcessExecutor();
        executor.setCertificateId(certificateId);
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        CertificateReports reports = executor.execute();

        SimpleCertificateReport simpleReport = reports.getSimpleReport();
        assertNotNull(simpleReport);

        assertEquals(QWACProfile.NOT_QWAC, simpleReport.getQWACProfile());
        assertEquals(QWACProfile.NOT_QWAC, simpleReport.getTLSBindingSignatureIssuerCertificateQWACProfile());

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(QWACProfile.NOT_QWAC, detailedReport.getCertificateQWACProfile(certificateId));

        XmlCertificate xmlCertificate = detailedReport.getXmlCertificateById(certificateId);
        assertNotNull(xmlCertificate);

        XmlQWACProcess qwacProcess = xmlCertificate.getQWACProcess();
        assertNotNull(qwacProcess);
        assertEquals(certificateId, qwacProcess.getId());
        assertEquals(QWACProfile.NOT_QWAC, qwacProcess.getQWACType());
        assertEquals(Indication.FAILED, qwacProcess.getConclusion().getIndication());

        boolean isQWACValidCheckFound = false;
        for (XmlConstraint xmlConstraint : qwacProcess.getConstraint()) {
            if (MessageTag.QWAC_VALID.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                assertEquals(MessageTag.QWAC_VALID_ANS.getId(), xmlConstraint.getError().getKey());
                isQWACValidCheckFound = true;
            }
        }
        assertTrue(isQWACValidCheckFound);

        // 1-qwac checks
        boolean is1QWACProcessPresent = false;
        boolean bbbCheckPresent = false;
        boolean qwac1DomainNamePresent = false;
        boolean linkHeaderPresent = false;
        boolean sigFormCheckPresent = false;
        boolean jadesCheckPresent = false;
        boolean jadesCompactCheckPresent = false;
        boolean expTimeCheckPresent = false;
        boolean sigExpCheckPresent = false;
        boolean qwac2CheckPresent = false;
        boolean sigValidCheckPresent = false;
        boolean tlsCertBindingValidCheckPresent = false;

        boolean isTlsSupportedBy2QWACProcessPresent = false;
        for (XmlValidationQWACProcess xmlValidationQWACProcess : qwacProcess.getValidationQWACProcess()) {
            if (i18nProvider.getMessage(MessageTag.QWAC_VALIDATION_PROFILE,
                    ValidationProcessUtils.getQWACValidationMessageTag(QWACProfile.QWAC_1)).equals(xmlValidationQWACProcess.getTitle())) {
                assertEquals(Indication.FAILED, xmlValidationQWACProcess.getConclusion().getIndication());
                is1QWACProcessPresent = true;

            } else if (i18nProvider.getMessage(MessageTag.QWAC_VALIDATION_PROFILE,
                    ValidationProcessUtils.getQWACValidationMessageTag(QWACProfile.TLS_BY_QWAC_2)).equals(xmlValidationQWACProcess.getTitle())) {
                assertEquals(Indication.FAILED, xmlValidationQWACProcess.getConclusion().getIndication());
                for (XmlConstraint xmlConstraint : xmlValidationQWACProcess.getConstraint()) {
                    if (MessageTag.BBB_ACCEPT.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        bbbCheckPresent = true;
                    } else if (MessageTag.QWAC_DOMAIN_NAME.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        qwac1DomainNamePresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_URL.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        linkHeaderPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        sigFormCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG_FORM.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        jadesCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG_SER.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        jadesCompactCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG_EXP.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        expTimeCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG_EXPIRY_DATE.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        sigExpCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_QWAC2.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                        assertEquals(MessageTag.TLS_CERT_BINDING_QWAC2_ANS.getId(), xmlConstraint.getError().getKey());
                        qwac2CheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG_VALID.getId().equals(xmlConstraint.getName().getKey())) {
                        sigValidCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_CERT_IDENTIFIED.getId().equals(xmlConstraint.getName().getKey())) {
                        tlsCertBindingValidCheckPresent = true;
                    }
                }

                isTlsSupportedBy2QWACProcessPresent = true;
            }
        }
        assertTrue(is1QWACProcessPresent);
        assertTrue(bbbCheckPresent);
        assertTrue(qwac1DomainNamePresent);
        assertTrue(linkHeaderPresent);
        assertTrue(sigFormCheckPresent);
        assertTrue(jadesCheckPresent);
        assertTrue(jadesCompactCheckPresent);
        assertTrue(expTimeCheckPresent);
        assertTrue(sigExpCheckPresent);
        assertTrue(qwac2CheckPresent);
        assertFalse(sigValidCheckPresent);
        assertFalse(tlsCertBindingValidCheckPresent);
        assertTrue(isTlsSupportedBy2QWACProcessPresent);

        XmlSignature tlsCertificateBindingSignature = diagnosticData
                .getConnectionInfo().getTLSCertificateBindingSignature().getSignature();

        XmlBasicBuildingBlocks sigBBB = detailedReport.getBasicBuildingBlockById(tlsCertificateBindingSignature.getId());
        assertNotNull(sigBBB);
        assertEquals(Indication.PASSED, sigBBB.getConclusion().getIndication());

        XmlSAV xmlSAV = sigBBB.getSAV();
        assertNotNull(xmlSAV);
        assertEquals(Indication.PASSED, xmlSAV.getConclusion().getIndication());

        boolean signCertCheckPresent = false;
        boolean signCertOnlyOneCheckPresent = false;
        boolean kidCheckPresent = false;
        boolean signTimeCheckPresent = false;
        boolean ctyCheckPresent = false;
        for (XmlConstraint xmlConstraint : xmlSAV.getConstraint()) {
            assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
            if (MessageTag.BBB_ICS_ISASCP.getId().equals(xmlConstraint.getName().getKey())) {
                signCertCheckPresent = true;
            } else if (MessageTag.BBB_ICS_ISASCPU.getId().equals(xmlConstraint.getName().getKey())) {
                signCertOnlyOneCheckPresent = true;
            } else if (MessageTag.BBB_ICS_ISAKIDP.getId().equals(xmlConstraint.getName().getKey())) {
                kidCheckPresent = true;
            } else if (MessageTag.BBB_SAV_ISQPSTP.getId().equals(xmlConstraint.getName().getKey())) {
                signTimeCheckPresent = true;
            } else if (MessageTag.BBB_SAV_ISQPCTP.getId().equals(xmlConstraint.getName().getKey())) {
                ctyCheckPresent = true;
            }
        }
        assertTrue(signCertCheckPresent);
        assertTrue(signCertOnlyOneCheckPresent);
        assertTrue(kidCheckPresent);
        assertTrue(signTimeCheckPresent);
        assertTrue(ctyCheckPresent);

        eu.europa.esig.dss.diagnostic.jaxb.XmlCertificate signingCertificate =
                tlsCertificateBindingSignature.getSigningCertificate().getCertificate();
        assertEquals(QWACProfile.NOT_QWAC, detailedReport.getCertificateQWACProfile(signingCertificate.getId()));

        eu.europa.esig.dss.detailedreport.jaxb.XmlSignature xmlSignature = detailedReport.getXmlSignatureById(tlsCertificateBindingSignature.getId());
        assertEquals(Indication.TOTAL_PASSED, xmlSignature.getConclusion().getIndication());

        XmlValidationSignatureQualification signatureQualification = xmlSignature.getValidationSignatureQualification();
        assertEquals(SignatureQualification.ADESIG_QC, signatureQualification.getSignatureQualification());

        XmlQWACProcess signatureQWACProcess = signatureQualification.getQWACProcess();
        assertEquals(signingCertificate.getId(), signatureQWACProcess.getId());
        assertEquals(QWACProfile.NOT_QWAC, signatureQWACProcess.getQWACType());
        assertEquals(Indication.FAILED, signatureQWACProcess.getConclusion().getIndication());

        // 2-qwac checks
        boolean certPolicyCheckPresent = false;
        boolean certQualConclusiveCheckPresent = false;
        boolean wsaCheckAtIssuanceTimePresent = false;
        boolean wsaCheckAtValidationTimePresent = false;
        boolean certValidityPeriodCheckPresent = false;
        boolean domainNamePresent = false;
        boolean extKeyUsageCheckPresent = false;
        boolean bbbCheckConclusive = false;
        boolean is2QWACProcessPresent = false;
        for (XmlValidationQWACProcess xmlValidationQWACProcess : signatureQWACProcess.getValidationQWACProcess()) {
            if (i18nProvider.getMessage(MessageTag.QWAC_VALIDATION_PROFILE,
                    ValidationProcessUtils.getQWACValidationMessageTag(QWACProfile.QWAC_2)).equals(xmlValidationQWACProcess.getTitle())) {
                assertEquals(Indication.FAILED, xmlValidationQWACProcess.getConclusion().getIndication());
                for (XmlConstraint xmlConstraint : xmlValidationQWACProcess.getConstraint()) {
                    if (MessageTag.QWAC_CERT_POLICY.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        certPolicyCheckPresent = true;
                    } else if (MessageTag.QWAC_CERT_QUAL_CONCLUSIVE.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        certQualConclusiveCheckPresent = true;
                    } else if (MessageTag.QWAC_IS_WSA_AT_TIME.getId().equals(xmlConstraint.getName().getKey())) {
                        if (i18nProvider.getMessage(MessageTag.QWAC_IS_WSA_AT_TIME, ValidationProcessUtils.getValidationTimeMessageTag(
                                ValidationTime.CERTIFICATE_ISSUANCE_TIME)).equals(xmlConstraint.getName().getValue())) {
                            assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                            assertEquals(MessageTag.QWAC_IS_WSA_AT_TIME_ANS.getId(), xmlConstraint.getError().getKey());
                            wsaCheckAtIssuanceTimePresent = true;
                        } else if (i18nProvider.getMessage(MessageTag.QWAC_IS_WSA_AT_TIME, ValidationProcessUtils.getValidationTimeMessageTag(
                                ValidationTime.VALIDATION_TIME)).equals(xmlConstraint.getName().getValue())) {
                            wsaCheckAtValidationTimePresent = true;
                        }
                    } else if (MessageTag.QWAC_VAL_PERIOD.getId().equals(xmlConstraint.getName().getKey())) {
                        certValidityPeriodCheckPresent = true;
                    } else if (MessageTag.QWAC_DOMAIN_NAME.getId().equals(xmlConstraint.getName().getKey())) {
                        domainNamePresent = true;
                    } else if (MessageTag.QWAC2_EXT_KEY_USAGE.getId().equals(xmlConstraint.getName().getKey())) {
                        extKeyUsageCheckPresent = true;
                    } else if (MessageTag.BBB_ACCEPT.getId().equals(xmlConstraint.getName().getKey())) {
                        bbbCheckConclusive = true;
                    }
                }

                is2QWACProcessPresent = true;
            }
        }
        assertTrue(certPolicyCheckPresent);
        assertTrue(certQualConclusiveCheckPresent);
        assertTrue(wsaCheckAtIssuanceTimePresent);
        assertFalse(wsaCheckAtValidationTimePresent);
        assertFalse(certValidityPeriodCheckPresent);
        assertFalse(domainNamePresent);
        assertFalse(extKeyUsageCheckPresent);
        assertFalse(bbbCheckConclusive);
        assertTrue(is2QWACProcessPresent);

        checkReports(reports);
    }

    @Test
    void qwac2CertExpTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/qwac-validation/2-qwac-valid-diag-data.xml"));
        assertNotNull(diagnosticData);

        XmlTLSCertificateBindingSignature bindingSignature = diagnosticData.getConnectionInfo().getTLSCertificateBindingSignature();
        bindingSignature.getSignature().setClaimedSigningTime(DSSUtils.getUtcDate(2025, Calendar.OCTOBER, 1));

        eu.europa.esig.dss.diagnostic.jaxb.XmlCertificate certificate = bindingSignature.getSignature().getSigningCertificate().getCertificate();
        certificate.setNotAfter(DSSUtils.getUtcDate(2025, Calendar.NOVEMBER, 1));

        String certificateId = "C-83D242F9A51C7A62BA1B774268EAAECBAB097479E83D8675C14F02DFB269FE77";

        EtsiValidationPolicy validationPolicy = loadDefaultPolicy();
        LevelConstraint levelConstraint = new LevelConstraint();
        levelConstraint.setLevel(Level.WARN);
        validationPolicy.getSignatureConstraints().getBasicSignatureConstraints().getSigningCertificate().setNotExpired(levelConstraint);
        validationPolicy.getSignatureConstraints().getBasicSignatureConstraints().getSigningCertificate().setAcceptableRevocationDataFound(levelConstraint);

        QWACCertificateProcessExecutor executor = new QWACCertificateProcessExecutor();
        executor.setCertificateId(certificateId);
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        CertificateReports reports = executor.execute();

        SimpleCertificateReport simpleReport = reports.getSimpleReport();
        assertNotNull(simpleReport);

        assertEquals(QWACProfile.NOT_QWAC, simpleReport.getQWACProfile());
        assertEquals(QWACProfile.NOT_QWAC, simpleReport.getTLSBindingSignatureIssuerCertificateQWACProfile());

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(QWACProfile.NOT_QWAC, detailedReport.getCertificateQWACProfile(certificateId));

        XmlCertificate xmlCertificate = detailedReport.getXmlCertificateById(certificateId);
        assertNotNull(xmlCertificate);

        XmlQWACProcess qwacProcess = xmlCertificate.getQWACProcess();
        assertNotNull(qwacProcess);
        assertEquals(certificateId, qwacProcess.getId());
        assertEquals(QWACProfile.NOT_QWAC, qwacProcess.getQWACType());
        assertEquals(Indication.FAILED, qwacProcess.getConclusion().getIndication());

        boolean isQWACValidCheckFound = false;
        for (XmlConstraint xmlConstraint : qwacProcess.getConstraint()) {
            if (MessageTag.QWAC_VALID.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                assertEquals(MessageTag.QWAC_VALID_ANS.getId(), xmlConstraint.getError().getKey());
                isQWACValidCheckFound = true;
            }
        }
        assertTrue(isQWACValidCheckFound);

        // 1-qwac checks
        boolean is1QWACProcessPresent = false;
        boolean bbbCheckPresent = false;
        boolean qwac1DomainNamePresent = false;
        boolean linkHeaderPresent = false;
        boolean sigFormCheckPresent = false;
        boolean jadesCheckPresent = false;
        boolean jadesCompactCheckPresent = false;
        boolean expTimeCheckPresent = false;
        boolean sigExpCheckPresent = false;
        boolean qwac2CheckPresent = false;
        boolean sigValidCheckPresent = false;
        boolean tlsCertBindingValidCheckPresent = false;

        boolean isTlsSupportedBy2QWACProcessPresent = false;
        for (XmlValidationQWACProcess xmlValidationQWACProcess : qwacProcess.getValidationQWACProcess()) {
            if (i18nProvider.getMessage(MessageTag.QWAC_VALIDATION_PROFILE,
                    ValidationProcessUtils.getQWACValidationMessageTag(QWACProfile.QWAC_1)).equals(xmlValidationQWACProcess.getTitle())) {
                assertEquals(Indication.FAILED, xmlValidationQWACProcess.getConclusion().getIndication());
                is1QWACProcessPresent = true;

            } else if (i18nProvider.getMessage(MessageTag.QWAC_VALIDATION_PROFILE,
                    ValidationProcessUtils.getQWACValidationMessageTag(QWACProfile.TLS_BY_QWAC_2)).equals(xmlValidationQWACProcess.getTitle())) {
                assertEquals(Indication.FAILED, xmlValidationQWACProcess.getConclusion().getIndication());
                for (XmlConstraint xmlConstraint : xmlValidationQWACProcess.getConstraint()) {
                    if (MessageTag.BBB_ACCEPT.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        bbbCheckPresent = true;
                    } else if (MessageTag.QWAC_DOMAIN_NAME.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        qwac1DomainNamePresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_URL.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        linkHeaderPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        sigFormCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG_FORM.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        jadesCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG_SER.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        jadesCompactCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG_EXP.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        expTimeCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG_EXPIRY_DATE.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                        assertEquals(MessageTag.TLS_CERT_BINDING_SIG_EXPIRY_DATE_ANS.getId(), xmlConstraint.getError().getKey());
                        sigExpCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_QWAC2.getId().equals(xmlConstraint.getName().getKey())) {
                        qwac2CheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG_VALID.getId().equals(xmlConstraint.getName().getKey())) {
                        sigValidCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_CERT_IDENTIFIED.getId().equals(xmlConstraint.getName().getKey())) {
                        tlsCertBindingValidCheckPresent = true;
                    }
                }

                isTlsSupportedBy2QWACProcessPresent = true;
            }
        }
        assertTrue(is1QWACProcessPresent);
        assertTrue(bbbCheckPresent);
        assertTrue(qwac1DomainNamePresent);
        assertTrue(linkHeaderPresent);
        assertTrue(sigFormCheckPresent);
        assertTrue(jadesCheckPresent);
        assertTrue(jadesCompactCheckPresent);
        assertTrue(expTimeCheckPresent);
        assertTrue(sigExpCheckPresent);
        assertFalse(qwac2CheckPresent);
        assertFalse(sigValidCheckPresent);
        assertFalse(tlsCertBindingValidCheckPresent);
        assertTrue(isTlsSupportedBy2QWACProcessPresent);

        XmlSignature tlsCertificateBindingSignature = diagnosticData
                .getConnectionInfo().getTLSCertificateBindingSignature().getSignature();

        XmlBasicBuildingBlocks sigBBB = detailedReport.getBasicBuildingBlockById(tlsCertificateBindingSignature.getId());
        assertNotNull(sigBBB);
        assertEquals(Indication.PASSED, sigBBB.getConclusion().getIndication());

        XmlSAV xmlSAV = sigBBB.getSAV();
        assertNotNull(xmlSAV);
        assertEquals(Indication.PASSED, xmlSAV.getConclusion().getIndication());

        boolean signCertCheckPresent = false;
        boolean signCertOnlyOneCheckPresent = false;
        boolean kidCheckPresent = false;
        boolean signTimeCheckPresent = false;
        boolean ctyCheckPresent = false;
        for (XmlConstraint xmlConstraint : xmlSAV.getConstraint()) {
            assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
            if (MessageTag.BBB_ICS_ISASCP.getId().equals(xmlConstraint.getName().getKey())) {
                signCertCheckPresent = true;
            } else if (MessageTag.BBB_ICS_ISASCPU.getId().equals(xmlConstraint.getName().getKey())) {
                signCertOnlyOneCheckPresent = true;
            } else if (MessageTag.BBB_ICS_ISAKIDP.getId().equals(xmlConstraint.getName().getKey())) {
                kidCheckPresent = true;
            } else if (MessageTag.BBB_SAV_ISQPSTP.getId().equals(xmlConstraint.getName().getKey())) {
                signTimeCheckPresent = true;
            } else if (MessageTag.BBB_SAV_ISQPCTP.getId().equals(xmlConstraint.getName().getKey())) {
                ctyCheckPresent = true;
            }
        }
        assertTrue(signCertCheckPresent);
        assertTrue(signCertOnlyOneCheckPresent);
        assertTrue(kidCheckPresent);
        assertTrue(signTimeCheckPresent);
        assertTrue(ctyCheckPresent);

        eu.europa.esig.dss.diagnostic.jaxb.XmlCertificate signingCertificate =
                tlsCertificateBindingSignature.getSigningCertificate().getCertificate();
        assertEquals(QWACProfile.NOT_QWAC, detailedReport.getCertificateQWACProfile(signingCertificate.getId()));

        eu.europa.esig.dss.detailedreport.jaxb.XmlSignature xmlSignature = detailedReport.getXmlSignatureById(tlsCertificateBindingSignature.getId());
        assertEquals(Indication.TOTAL_PASSED, xmlSignature.getConclusion().getIndication());

        XmlValidationSignatureQualification signatureQualification = xmlSignature.getValidationSignatureQualification();
        assertEquals(SignatureQualification.NOT_ADES, signatureQualification.getSignatureQualification());

        XmlQWACProcess signatureQWACProcess = signatureQualification.getQWACProcess();
        assertEquals(signingCertificate.getId(), signatureQWACProcess.getId());
        assertEquals(QWACProfile.NOT_QWAC, signatureQWACProcess.getQWACType());
        assertEquals(Indication.FAILED, signatureQWACProcess.getConclusion().getIndication());

        // 2-qwac checks
        boolean certPolicyCheckPresent = false;
        boolean certQualConclusiveCheckPresent = false;
        boolean wsaCheckAtIssuanceTimePresent = false;
        boolean wsaCheckAtValidationTimePresent = false;
        boolean certValidityPeriodCheckPresent = false;
        boolean domainNamePresent = false;
        boolean extKeyUsageCheckPresent = false;
        boolean bbbCheckConclusive = false;
        boolean is2QWACProcessPresent = false;
        for (XmlValidationQWACProcess xmlValidationQWACProcess : signatureQWACProcess.getValidationQWACProcess()) {
            if (i18nProvider.getMessage(MessageTag.QWAC_VALIDATION_PROFILE,
                    ValidationProcessUtils.getQWACValidationMessageTag(QWACProfile.QWAC_2)).equals(xmlValidationQWACProcess.getTitle())) {
                assertEquals(Indication.FAILED, xmlValidationQWACProcess.getConclusion().getIndication());
                for (XmlConstraint xmlConstraint : xmlValidationQWACProcess.getConstraint()) {
                    if (MessageTag.QWAC_CERT_POLICY.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        certPolicyCheckPresent = true;
                    } else if (MessageTag.QWAC_CERT_QUAL_CONCLUSIVE.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        certQualConclusiveCheckPresent = true;
                    } else if (MessageTag.QWAC_IS_WSA_AT_TIME.getId().equals(xmlConstraint.getName().getKey())) {
                        if (i18nProvider.getMessage(MessageTag.QWAC_IS_WSA_AT_TIME, ValidationProcessUtils.getValidationTimeMessageTag(
                                ValidationTime.CERTIFICATE_ISSUANCE_TIME)).equals(xmlConstraint.getName().getValue())) {
                            assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                            wsaCheckAtIssuanceTimePresent = true;
                        } else if (i18nProvider.getMessage(MessageTag.QWAC_IS_WSA_AT_TIME, ValidationProcessUtils.getValidationTimeMessageTag(
                                ValidationTime.VALIDATION_TIME)).equals(xmlConstraint.getName().getValue())) {
                            assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                            wsaCheckAtValidationTimePresent = true;
                        }
                    } else if (MessageTag.QWAC_VAL_PERIOD.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                        assertEquals(MessageTag.QWAC_VAL_PERIOD_ANS.getId(), xmlConstraint.getError().getKey());
                        certValidityPeriodCheckPresent = true;
                    } else if (MessageTag.QWAC_DOMAIN_NAME.getId().equals(xmlConstraint.getName().getKey())) {
                        domainNamePresent = true;
                    } else if (MessageTag.QWAC2_EXT_KEY_USAGE.getId().equals(xmlConstraint.getName().getKey())) {
                        extKeyUsageCheckPresent = true;
                    } else if (MessageTag.BBB_ACCEPT.getId().equals(xmlConstraint.getName().getKey())) {
                        bbbCheckConclusive = true;
                    }
                }

                is2QWACProcessPresent = true;
            }
        }
        assertTrue(certPolicyCheckPresent);
        assertTrue(certQualConclusiveCheckPresent);
        assertTrue(wsaCheckAtIssuanceTimePresent);
        assertTrue(wsaCheckAtValidationTimePresent);
        assertTrue(certValidityPeriodCheckPresent);
        assertFalse(domainNamePresent);
        assertFalse(extKeyUsageCheckPresent);
        assertFalse(bbbCheckConclusive);
        assertTrue(is2QWACProcessPresent);

        checkReports(reports);
    }

    @Test
    void qwac2DomainNameTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/qwac-validation/2-qwac-valid-diag-data.xml"));
        assertNotNull(diagnosticData);

        XmlTLSCertificateBindingSignature bindingSignature = diagnosticData.getConnectionInfo().getTLSCertificateBindingSignature();

        eu.europa.esig.dss.diagnostic.jaxb.XmlCertificate certificate = bindingSignature.getSignature().getSigningCertificate().getCertificate();
        for (XmlCertificateExtension certificateExtension : certificate.getCertificateExtensions()) {
            if (CertificateExtensionEnum.SUBJECT_ALTERNATIVE_NAME.getOid().equals(certificateExtension.getOID())) {
                XmlSubjectAlternativeNames xmlSubjectAlternativeNames = (XmlSubjectAlternativeNames) certificateExtension;
                XmlGeneralName xmlGeneralName = new XmlGeneralName();
                xmlGeneralName.setType(GeneralNameType.DNS_NAME);
                xmlGeneralName.setValue("wikipedia.com");
                xmlSubjectAlternativeNames.getSubjectAlternativeName().clear();
                xmlSubjectAlternativeNames.getSubjectAlternativeName().add(xmlGeneralName);
            }
        }

        String certificateId = "C-83D242F9A51C7A62BA1B774268EAAECBAB097479E83D8675C14F02DFB269FE77";

        QWACCertificateProcessExecutor executor = new QWACCertificateProcessExecutor();
        executor.setCertificateId(certificateId);
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        CertificateReports reports = executor.execute();

        SimpleCertificateReport simpleReport = reports.getSimpleReport();
        assertNotNull(simpleReport);

        assertEquals(QWACProfile.NOT_QWAC, simpleReport.getQWACProfile());
        assertEquals(QWACProfile.NOT_QWAC, simpleReport.getTLSBindingSignatureIssuerCertificateQWACProfile());

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(QWACProfile.NOT_QWAC, detailedReport.getCertificateQWACProfile(certificateId));

        XmlCertificate xmlCertificate = detailedReport.getXmlCertificateById(certificateId);
        assertNotNull(xmlCertificate);

        XmlQWACProcess qwacProcess = xmlCertificate.getQWACProcess();
        assertNotNull(qwacProcess);
        assertEquals(certificateId, qwacProcess.getId());
        assertEquals(QWACProfile.NOT_QWAC, qwacProcess.getQWACType());
        assertEquals(Indication.FAILED, qwacProcess.getConclusion().getIndication());

        boolean isQWACValidCheckFound = false;
        for (XmlConstraint xmlConstraint : qwacProcess.getConstraint()) {
            if (MessageTag.QWAC_VALID.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                assertEquals(MessageTag.QWAC_VALID_ANS.getId(), xmlConstraint.getError().getKey());
                isQWACValidCheckFound = true;
            }
        }
        assertTrue(isQWACValidCheckFound);

        // 1-qwac checks
        boolean is1QWACProcessPresent = false;
        boolean bbbCheckPresent = false;
        boolean qwac1DomainNamePresent = false;
        boolean linkHeaderPresent = false;
        boolean sigFormCheckPresent = false;
        boolean jadesCheckPresent = false;
        boolean jadesCompactCheckPresent = false;
        boolean expTimeCheckPresent = false;
        boolean sigExpCheckPresent = false;
        boolean qwac2CheckPresent = false;
        boolean sigValidCheckPresent = false;
        boolean tlsCertBindingValidCheckPresent = false;

        boolean isTlsSupportedBy2QWACProcessPresent = false;
        for (XmlValidationQWACProcess xmlValidationQWACProcess : qwacProcess.getValidationQWACProcess()) {
            if (i18nProvider.getMessage(MessageTag.QWAC_VALIDATION_PROFILE,
                    ValidationProcessUtils.getQWACValidationMessageTag(QWACProfile.QWAC_1)).equals(xmlValidationQWACProcess.getTitle())) {
                assertEquals(Indication.FAILED, xmlValidationQWACProcess.getConclusion().getIndication());
                is1QWACProcessPresent = true;

            } else if (i18nProvider.getMessage(MessageTag.QWAC_VALIDATION_PROFILE,
                    ValidationProcessUtils.getQWACValidationMessageTag(QWACProfile.TLS_BY_QWAC_2)).equals(xmlValidationQWACProcess.getTitle())) {
                assertEquals(Indication.FAILED, xmlValidationQWACProcess.getConclusion().getIndication());
                for (XmlConstraint xmlConstraint : xmlValidationQWACProcess.getConstraint()) {
                    if (MessageTag.BBB_ACCEPT.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        bbbCheckPresent = true;
                    } else if (MessageTag.QWAC_DOMAIN_NAME.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        qwac1DomainNamePresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_URL.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        linkHeaderPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        sigFormCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG_FORM.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        jadesCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG_SER.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        jadesCompactCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG_EXP.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        expTimeCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG_EXPIRY_DATE.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        sigExpCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_QWAC2.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                        assertEquals(MessageTag.TLS_CERT_BINDING_QWAC2_ANS.getId(), xmlConstraint.getError().getKey());
                        qwac2CheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG_VALID.getId().equals(xmlConstraint.getName().getKey())) {
                        sigValidCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_CERT_IDENTIFIED.getId().equals(xmlConstraint.getName().getKey())) {
                        tlsCertBindingValidCheckPresent = true;
                    }
                }

                isTlsSupportedBy2QWACProcessPresent = true;
            }
        }
        assertTrue(is1QWACProcessPresent);
        assertTrue(bbbCheckPresent);
        assertTrue(qwac1DomainNamePresent);
        assertTrue(linkHeaderPresent);
        assertTrue(sigFormCheckPresent);
        assertTrue(jadesCheckPresent);
        assertTrue(jadesCompactCheckPresent);
        assertTrue(expTimeCheckPresent);
        assertTrue(sigExpCheckPresent);
        assertTrue(qwac2CheckPresent);
        assertFalse(sigValidCheckPresent);
        assertFalse(tlsCertBindingValidCheckPresent);
        assertTrue(isTlsSupportedBy2QWACProcessPresent);

        XmlSignature tlsCertificateBindingSignature = diagnosticData
                .getConnectionInfo().getTLSCertificateBindingSignature().getSignature();

        XmlBasicBuildingBlocks sigBBB = detailedReport.getBasicBuildingBlockById(tlsCertificateBindingSignature.getId());
        assertNotNull(sigBBB);
        assertEquals(Indication.PASSED, sigBBB.getConclusion().getIndication());

        XmlSAV xmlSAV = sigBBB.getSAV();
        assertNotNull(xmlSAV);
        assertEquals(Indication.PASSED, xmlSAV.getConclusion().getIndication());

        boolean signCertCheckPresent = false;
        boolean signCertOnlyOneCheckPresent = false;
        boolean kidCheckPresent = false;
        boolean signTimeCheckPresent = false;
        boolean ctyCheckPresent = false;
        for (XmlConstraint xmlConstraint : xmlSAV.getConstraint()) {
            assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
            if (MessageTag.BBB_ICS_ISASCP.getId().equals(xmlConstraint.getName().getKey())) {
                signCertCheckPresent = true;
            } else if (MessageTag.BBB_ICS_ISASCPU.getId().equals(xmlConstraint.getName().getKey())) {
                signCertOnlyOneCheckPresent = true;
            } else if (MessageTag.BBB_ICS_ISAKIDP.getId().equals(xmlConstraint.getName().getKey())) {
                kidCheckPresent = true;
            } else if (MessageTag.BBB_SAV_ISQPSTP.getId().equals(xmlConstraint.getName().getKey())) {
                signTimeCheckPresent = true;
            } else if (MessageTag.BBB_SAV_ISQPCTP.getId().equals(xmlConstraint.getName().getKey())) {
                ctyCheckPresent = true;
            }
        }
        assertTrue(signCertCheckPresent);
        assertTrue(signCertOnlyOneCheckPresent);
        assertTrue(kidCheckPresent);
        assertTrue(signTimeCheckPresent);
        assertTrue(ctyCheckPresent);

        eu.europa.esig.dss.diagnostic.jaxb.XmlCertificate signingCertificate =
                tlsCertificateBindingSignature.getSigningCertificate().getCertificate();
        assertEquals(QWACProfile.NOT_QWAC, detailedReport.getCertificateQWACProfile(signingCertificate.getId()));

        eu.europa.esig.dss.detailedreport.jaxb.XmlSignature xmlSignature = detailedReport.getXmlSignatureById(tlsCertificateBindingSignature.getId());
        assertEquals(Indication.TOTAL_PASSED, xmlSignature.getConclusion().getIndication());

        XmlValidationSignatureQualification signatureQualification = xmlSignature.getValidationSignatureQualification();
        assertEquals(SignatureQualification.NOT_ADES, signatureQualification.getSignatureQualification());

        XmlQWACProcess signatureQWACProcess = signatureQualification.getQWACProcess();
        assertEquals(signingCertificate.getId(), signatureQWACProcess.getId());
        assertEquals(QWACProfile.NOT_QWAC, signatureQWACProcess.getQWACType());
        assertEquals(Indication.FAILED, signatureQWACProcess.getConclusion().getIndication());

        // 2-qwac checks
        boolean certPolicyCheckPresent = false;
        boolean certQualConclusiveCheckPresent = false;
        boolean wsaCheckAtIssuanceTimePresent = false;
        boolean wsaCheckAtValidationTimePresent = false;
        boolean certValidityPeriodCheckPresent = false;
        boolean domainNamePresent = false;
        boolean extKeyUsageCheckPresent = false;
        boolean bbbCheckConclusive = false;
        boolean is2QWACProcessPresent = false;
        for (XmlValidationQWACProcess xmlValidationQWACProcess : signatureQWACProcess.getValidationQWACProcess()) {
            if (i18nProvider.getMessage(MessageTag.QWAC_VALIDATION_PROFILE,
                    ValidationProcessUtils.getQWACValidationMessageTag(QWACProfile.QWAC_2)).equals(xmlValidationQWACProcess.getTitle())) {
                assertEquals(Indication.FAILED, xmlValidationQWACProcess.getConclusion().getIndication());
                for (XmlConstraint xmlConstraint : xmlValidationQWACProcess.getConstraint()) {
                    if (MessageTag.QWAC_CERT_POLICY.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        certPolicyCheckPresent = true;
                    } else if (MessageTag.QWAC_CERT_QUAL_CONCLUSIVE.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        certQualConclusiveCheckPresent = true;
                    } else if (MessageTag.QWAC_IS_WSA_AT_TIME.getId().equals(xmlConstraint.getName().getKey())) {
                        if (i18nProvider.getMessage(MessageTag.QWAC_IS_WSA_AT_TIME, ValidationProcessUtils.getValidationTimeMessageTag(
                                ValidationTime.CERTIFICATE_ISSUANCE_TIME)).equals(xmlConstraint.getName().getValue())) {
                            assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                            wsaCheckAtIssuanceTimePresent = true;
                        } else if (i18nProvider.getMessage(MessageTag.QWAC_IS_WSA_AT_TIME, ValidationProcessUtils.getValidationTimeMessageTag(
                                ValidationTime.VALIDATION_TIME)).equals(xmlConstraint.getName().getValue())) {
                            assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                            wsaCheckAtValidationTimePresent = true;
                        }
                    } else if (MessageTag.QWAC_VAL_PERIOD.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        certValidityPeriodCheckPresent = true;
                    } else if (MessageTag.QWAC_DOMAIN_NAME.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                        assertEquals(MessageTag.QWAC_DOMAIN_NAME_ANS.getId(), xmlConstraint.getError().getKey());
                        domainNamePresent = true;
                    } else if (MessageTag.QWAC2_EXT_KEY_USAGE.getId().equals(xmlConstraint.getName().getKey())) {
                        extKeyUsageCheckPresent = true;
                    } else if (MessageTag.BBB_ACCEPT.getId().equals(xmlConstraint.getName().getKey())) {
                        bbbCheckConclusive = true;
                    }
                }

                is2QWACProcessPresent = true;
            }
        }
        assertTrue(certPolicyCheckPresent);
        assertTrue(certQualConclusiveCheckPresent);
        assertTrue(wsaCheckAtIssuanceTimePresent);
        assertTrue(wsaCheckAtValidationTimePresent);
        assertTrue(certValidityPeriodCheckPresent);
        assertTrue(domainNamePresent);
        assertFalse(extKeyUsageCheckPresent);
        assertFalse(bbbCheckConclusive);
        assertTrue(is2QWACProcessPresent);

        checkReports(reports);
    }

    @Test
    void qwac2CertRevokedTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/qwac-validation/2-qwac-valid-diag-data.xml"));
        assertNotNull(diagnosticData);

        XmlTLSCertificateBindingSignature bindingSignature = diagnosticData.getConnectionInfo().getTLSCertificateBindingSignature();

        eu.europa.esig.dss.diagnostic.jaxb.XmlCertificate certificate = bindingSignature.getSignature().getSigningCertificate().getCertificate();
        List<XmlCertificateRevocation> revocations = certificate.getRevocations();
        XmlCertificateRevocation xmlCertificateRevocation = revocations.get(0);
        xmlCertificateRevocation.setStatus(CertificateStatus.REVOKED);
        xmlCertificateRevocation.setReason(RevocationReason.SUPERSEDED);
        Calendar calendar = Calendar.getInstance();
        calendar.setTime(diagnosticData.getValidationDate());
        calendar.add(Calendar.MONTH, -1);
        xmlCertificateRevocation.setRevocationDate(calendar.getTime());

        String certificateId = "C-83D242F9A51C7A62BA1B774268EAAECBAB097479E83D8675C14F02DFB269FE77";

        QWACCertificateProcessExecutor executor = new QWACCertificateProcessExecutor();
        executor.setCertificateId(certificateId);
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        CertificateReports reports = executor.execute();

        SimpleCertificateReport simpleReport = reports.getSimpleReport();
        assertNotNull(simpleReport);

        assertEquals(QWACProfile.NOT_QWAC, simpleReport.getQWACProfile());
        assertEquals(QWACProfile.NOT_QWAC, simpleReport.getTLSBindingSignatureIssuerCertificateQWACProfile());

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(QWACProfile.NOT_QWAC, detailedReport.getCertificateQWACProfile(certificateId));

        XmlCertificate xmlCertificate = detailedReport.getXmlCertificateById(certificateId);
        assertNotNull(xmlCertificate);

        XmlQWACProcess qwacProcess = xmlCertificate.getQWACProcess();
        assertNotNull(qwacProcess);
        assertEquals(certificateId, qwacProcess.getId());
        assertEquals(QWACProfile.NOT_QWAC, qwacProcess.getQWACType());
        assertEquals(Indication.FAILED, qwacProcess.getConclusion().getIndication());

        boolean isQWACValidCheckFound = false;
        for (XmlConstraint xmlConstraint : qwacProcess.getConstraint()) {
            if (MessageTag.QWAC_VALID.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                assertEquals(MessageTag.QWAC_VALID_ANS.getId(), xmlConstraint.getError().getKey());
                isQWACValidCheckFound = true;
            }
        }
        assertTrue(isQWACValidCheckFound);

        // 1-qwac checks
        boolean is1QWACProcessPresent = false;
        boolean bbbCheckPresent = false;
        boolean qwac1DomainNamePresent = false;
        boolean linkHeaderPresent = false;
        boolean sigFormCheckPresent = false;
        boolean jadesCheckPresent = false;
        boolean jadesCompactCheckPresent = false;
        boolean expTimeCheckPresent = false;
        boolean sigExpCheckPresent = false;
        boolean qwac2CheckPresent = false;
        boolean sigValidCheckPresent = false;
        boolean tlsCertBindingValidCheckPresent = false;

        boolean isTlsSupportedBy2QWACProcessPresent = false;
        for (XmlValidationQWACProcess xmlValidationQWACProcess : qwacProcess.getValidationQWACProcess()) {
            if (i18nProvider.getMessage(MessageTag.QWAC_VALIDATION_PROFILE,
                    ValidationProcessUtils.getQWACValidationMessageTag(QWACProfile.QWAC_1)).equals(xmlValidationQWACProcess.getTitle())) {
                assertEquals(Indication.FAILED, xmlValidationQWACProcess.getConclusion().getIndication());
                is1QWACProcessPresent = true;

            } else if (i18nProvider.getMessage(MessageTag.QWAC_VALIDATION_PROFILE,
                    ValidationProcessUtils.getQWACValidationMessageTag(QWACProfile.TLS_BY_QWAC_2)).equals(xmlValidationQWACProcess.getTitle())) {
                assertEquals(Indication.FAILED, xmlValidationQWACProcess.getConclusion().getIndication());
                for (XmlConstraint xmlConstraint : xmlValidationQWACProcess.getConstraint()) {
                    if (MessageTag.BBB_ACCEPT.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        bbbCheckPresent = true;
                    } else if (MessageTag.QWAC_DOMAIN_NAME.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        qwac1DomainNamePresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_URL.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        linkHeaderPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        sigFormCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG_FORM.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        jadesCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG_SER.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        jadesCompactCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG_EXP.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        expTimeCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG_EXPIRY_DATE.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        sigExpCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_QWAC2.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                        assertEquals(MessageTag.TLS_CERT_BINDING_QWAC2_ANS.getId(), xmlConstraint.getError().getKey());
                        qwac2CheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG_VALID.getId().equals(xmlConstraint.getName().getKey())) {
                        sigValidCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_CERT_IDENTIFIED.getId().equals(xmlConstraint.getName().getKey())) {
                        tlsCertBindingValidCheckPresent = true;
                    }
                }

                isTlsSupportedBy2QWACProcessPresent = true;
            }
        }
        assertTrue(is1QWACProcessPresent);
        assertTrue(bbbCheckPresent);
        assertTrue(qwac1DomainNamePresent);
        assertTrue(linkHeaderPresent);
        assertTrue(sigFormCheckPresent);
        assertTrue(jadesCheckPresent);
        assertTrue(jadesCompactCheckPresent);
        assertTrue(expTimeCheckPresent);
        assertTrue(sigExpCheckPresent);
        assertTrue(qwac2CheckPresent);
        assertFalse(sigValidCheckPresent);
        assertFalse(tlsCertBindingValidCheckPresent);
        assertTrue(isTlsSupportedBy2QWACProcessPresent);

        XmlSignature tlsCertificateBindingSignature = diagnosticData
                .getConnectionInfo().getTLSCertificateBindingSignature().getSignature();

        XmlBasicBuildingBlocks sigBBB = detailedReport.getBasicBuildingBlockById(tlsCertificateBindingSignature.getId());
        assertNotNull(sigBBB);
        assertEquals(Indication.INDETERMINATE, sigBBB.getConclusion().getIndication());
        assertEquals(SubIndication.REVOKED_NO_POE, sigBBB.getConclusion().getSubIndication());

        XmlSAV xmlSAV = sigBBB.getSAV();
        assertNotNull(xmlSAV);
        assertEquals(Indication.PASSED, xmlSAV.getConclusion().getIndication());

        boolean signCertCheckPresent = false;
        boolean signCertOnlyOneCheckPresent = false;
        boolean kidCheckPresent = false;
        boolean signTimeCheckPresent = false;
        boolean ctyCheckPresent = false;
        for (XmlConstraint xmlConstraint : xmlSAV.getConstraint()) {
            assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
            if (MessageTag.BBB_ICS_ISASCP.getId().equals(xmlConstraint.getName().getKey())) {
                signCertCheckPresent = true;
            } else if (MessageTag.BBB_ICS_ISASCPU.getId().equals(xmlConstraint.getName().getKey())) {
                signCertOnlyOneCheckPresent = true;
            } else if (MessageTag.BBB_ICS_ISAKIDP.getId().equals(xmlConstraint.getName().getKey())) {
                kidCheckPresent = true;
            } else if (MessageTag.BBB_SAV_ISQPSTP.getId().equals(xmlConstraint.getName().getKey())) {
                signTimeCheckPresent = true;
            } else if (MessageTag.BBB_SAV_ISQPCTP.getId().equals(xmlConstraint.getName().getKey())) {
                ctyCheckPresent = true;
            }
        }
        assertTrue(signCertCheckPresent);
        assertTrue(signCertOnlyOneCheckPresent);
        assertTrue(kidCheckPresent);
        assertTrue(signTimeCheckPresent);
        assertTrue(ctyCheckPresent);

        eu.europa.esig.dss.diagnostic.jaxb.XmlCertificate signingCertificate =
                tlsCertificateBindingSignature.getSigningCertificate().getCertificate();
        assertEquals(QWACProfile.NOT_QWAC, detailedReport.getCertificateQWACProfile(signingCertificate.getId()));

        eu.europa.esig.dss.detailedreport.jaxb.XmlSignature xmlSignature = detailedReport.getXmlSignatureById(tlsCertificateBindingSignature.getId());
        assertEquals(Indication.INDETERMINATE, xmlSignature.getConclusion().getIndication());
        assertEquals(SubIndication.REVOKED_NO_POE, xmlSignature.getConclusion().getSubIndication());

        XmlValidationSignatureQualification signatureQualification = xmlSignature.getValidationSignatureQualification();
        assertEquals(SignatureQualification.NOT_ADES, signatureQualification.getSignatureQualification());

        XmlQWACProcess signatureQWACProcess = signatureQualification.getQWACProcess();
        assertEquals(signingCertificate.getId(), signatureQWACProcess.getId());
        assertEquals(QWACProfile.NOT_QWAC, signatureQWACProcess.getQWACType());
        assertEquals(Indication.FAILED, signatureQWACProcess.getConclusion().getIndication());

        // 2-qwac checks
        boolean certPolicyCheckPresent = false;
        boolean certQualConclusiveCheckPresent = false;
        boolean wsaCheckAtIssuanceTimePresent = false;
        boolean wsaCheckAtValidationTimePresent = false;
        boolean certValidityPeriodCheckPresent = false;
        boolean domainNamePresent = false;
        boolean extKeyUsageCheckPresent = false;
        boolean bbbCheckConclusive = false;
        boolean is2QWACProcessPresent = false;
        for (XmlValidationQWACProcess xmlValidationQWACProcess : signatureQWACProcess.getValidationQWACProcess()) {
            if (i18nProvider.getMessage(MessageTag.QWAC_VALIDATION_PROFILE,
                    ValidationProcessUtils.getQWACValidationMessageTag(QWACProfile.QWAC_2)).equals(xmlValidationQWACProcess.getTitle())) {
                assertEquals(Indication.INDETERMINATE, xmlValidationQWACProcess.getConclusion().getIndication());
                for (XmlConstraint xmlConstraint : xmlValidationQWACProcess.getConstraint()) {
                    if (MessageTag.QWAC_CERT_POLICY.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        certPolicyCheckPresent = true;
                    } else if (MessageTag.QWAC_CERT_QUAL_CONCLUSIVE.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        certQualConclusiveCheckPresent = true;
                    } else if (MessageTag.QWAC_IS_WSA_AT_TIME.getId().equals(xmlConstraint.getName().getKey())) {
                        if (i18nProvider.getMessage(MessageTag.QWAC_IS_WSA_AT_TIME, ValidationProcessUtils.getValidationTimeMessageTag(
                                ValidationTime.CERTIFICATE_ISSUANCE_TIME)).equals(xmlConstraint.getName().getValue())) {
                            assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                            wsaCheckAtIssuanceTimePresent = true;
                        } else if (i18nProvider.getMessage(MessageTag.QWAC_IS_WSA_AT_TIME, ValidationProcessUtils.getValidationTimeMessageTag(
                                ValidationTime.VALIDATION_TIME)).equals(xmlConstraint.getName().getValue())) {
                            assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                            wsaCheckAtValidationTimePresent = true;
                        }
                    } else if (MessageTag.QWAC_VAL_PERIOD.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        certValidityPeriodCheckPresent = true;
                    } else if (MessageTag.QWAC_DOMAIN_NAME.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        domainNamePresent = true;
                    } else if (MessageTag.QWAC2_EXT_KEY_USAGE.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        extKeyUsageCheckPresent = true;
                    } else if (MessageTag.BBB_ACCEPT.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                        assertEquals(MessageTag.BBB_ACCEPT_ANS.getId(), xmlConstraint.getError().getKey());
                        bbbCheckConclusive = true;
                    }
                }

                is2QWACProcessPresent = true;
            }
        }
        assertTrue(certPolicyCheckPresent);
        assertTrue(certQualConclusiveCheckPresent);
        assertTrue(wsaCheckAtIssuanceTimePresent);
        assertTrue(wsaCheckAtValidationTimePresent);
        assertTrue(certValidityPeriodCheckPresent);
        assertTrue(domainNamePresent);
        assertTrue(extKeyUsageCheckPresent);
        assertTrue(bbbCheckConclusive);
        assertTrue(is2QWACProcessPresent);

        checkReports(reports);
    }

    @Test
    void sigNotSignCertTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/qwac-validation/2-qwac-valid-diag-data.xml"));
        assertNotNull(diagnosticData);

        XmlTLSCertificateBindingSignature bindingSignature = diagnosticData.getConnectionInfo().getTLSCertificateBindingSignature();
        XmlFoundCertificates foundCertificates = bindingSignature.getSignature().getFoundCertificates();
        for (XmlRelatedCertificate relatedCertificate : foundCertificates.getRelatedCertificates()) {
            relatedCertificate.getCertificateRefs().clear();
        }

        String certificateId = "C-83D242F9A51C7A62BA1B774268EAAECBAB097479E83D8675C14F02DFB269FE77";

        QWACCertificateProcessExecutor executor = new QWACCertificateProcessExecutor();
        executor.setCertificateId(certificateId);
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        CertificateReports reports = executor.execute();

        SimpleCertificateReport simpleReport = reports.getSimpleReport();
        assertNotNull(simpleReport);

        assertEquals(QWACProfile.NOT_QWAC, simpleReport.getQWACProfile());
        assertEquals(QWACProfile.QWAC_2, simpleReport.getTLSBindingSignatureIssuerCertificateQWACProfile());

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(QWACProfile.NOT_QWAC, detailedReport.getCertificateQWACProfile(certificateId));

        XmlCertificate xmlCertificate = detailedReport.getXmlCertificateById(certificateId);
        assertNotNull(xmlCertificate);

        XmlQWACProcess qwacProcess = xmlCertificate.getQWACProcess();
        assertNotNull(qwacProcess);
        assertEquals(certificateId, qwacProcess.getId());
        assertEquals(QWACProfile.NOT_QWAC, qwacProcess.getQWACType());
        assertEquals(Indication.FAILED, qwacProcess.getConclusion().getIndication());

        boolean isQWACValidCheckFound = false;
        for (XmlConstraint xmlConstraint : qwacProcess.getConstraint()) {
            if (MessageTag.QWAC_VALID.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                assertEquals(MessageTag.QWAC_VALID_ANS.getId(), xmlConstraint.getError().getKey());
                isQWACValidCheckFound = true;
            }
        }
        assertTrue(isQWACValidCheckFound);

        // 1-qwac checks
        boolean is1QWACProcessPresent = false;
        boolean bbbCheckPresent = false;
        boolean qwac1DomainNamePresent = false;
        boolean linkHeaderPresent = false;
        boolean sigFormCheckPresent = false;
        boolean jadesCheckPresent = false;
        boolean jadesCompactCheckPresent = false;
        boolean expTimeCheckPresent = false;
        boolean sigExpCheckPresent = false;
        boolean qwac2CheckPresent = false;
        boolean sigValidCheckPresent = false;
        boolean tlsCertBindingValidCheckPresent = false;

        boolean isTlsSupportedBy2QWACProcessPresent = false;
        for (XmlValidationQWACProcess xmlValidationQWACProcess : qwacProcess.getValidationQWACProcess()) {
            if (i18nProvider.getMessage(MessageTag.QWAC_VALIDATION_PROFILE,
                    ValidationProcessUtils.getQWACValidationMessageTag(QWACProfile.QWAC_1)).equals(xmlValidationQWACProcess.getTitle())) {
                assertEquals(Indication.FAILED, xmlValidationQWACProcess.getConclusion().getIndication());
                is1QWACProcessPresent = true;

            } else if (i18nProvider.getMessage(MessageTag.QWAC_VALIDATION_PROFILE,
                    ValidationProcessUtils.getQWACValidationMessageTag(QWACProfile.TLS_BY_QWAC_2)).equals(xmlValidationQWACProcess.getTitle())) {
                assertEquals(Indication.FAILED, xmlValidationQWACProcess.getConclusion().getIndication());
                for (XmlConstraint xmlConstraint : xmlValidationQWACProcess.getConstraint()) {
                    if (MessageTag.BBB_ACCEPT.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        bbbCheckPresent = true;
                    } else if (MessageTag.QWAC_DOMAIN_NAME.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        qwac1DomainNamePresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_URL.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        linkHeaderPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        sigFormCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG_FORM.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        jadesCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG_SER.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        jadesCompactCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG_EXP.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        expTimeCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG_EXPIRY_DATE.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        sigExpCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_QWAC2.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        qwac2CheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG_VALID.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                        assertEquals(MessageTag.TLS_CERT_BINDING_SIG_VALID_ANS.getId(), xmlConstraint.getError().getKey());
                        sigValidCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_CERT_IDENTIFIED.getId().equals(xmlConstraint.getName().getKey())) {
                        tlsCertBindingValidCheckPresent = true;
                    }
                }

                isTlsSupportedBy2QWACProcessPresent = true;
            }
        }
        assertTrue(is1QWACProcessPresent);
        assertTrue(bbbCheckPresent);
        assertTrue(qwac1DomainNamePresent);
        assertTrue(linkHeaderPresent);
        assertTrue(sigFormCheckPresent);
        assertTrue(jadesCheckPresent);
        assertTrue(jadesCompactCheckPresent);
        assertTrue(expTimeCheckPresent);
        assertTrue(sigExpCheckPresent);
        assertTrue(qwac2CheckPresent);
        assertTrue(sigValidCheckPresent);
        assertFalse(tlsCertBindingValidCheckPresent);
        assertTrue(isTlsSupportedBy2QWACProcessPresent);

        XmlSignature tlsCertificateBindingSignature = diagnosticData
                .getConnectionInfo().getTLSCertificateBindingSignature().getSignature();

        XmlBasicBuildingBlocks sigBBB = detailedReport.getBasicBuildingBlockById(tlsCertificateBindingSignature.getId());
        assertNotNull(sigBBB);
        assertEquals(Indication.INDETERMINATE, sigBBB.getConclusion().getIndication());
        assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, sigBBB.getConclusion().getSubIndication());

        XmlSAV xmlSAV = sigBBB.getSAV();
        assertNotNull(xmlSAV);
        assertEquals(Indication.INDETERMINATE, xmlSAV.getConclusion().getIndication());
        assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, xmlSAV.getConclusion().getSubIndication());

        boolean signCertCheckPresent = false;
        boolean signCertOnlyOneCheckPresent = false;
        boolean kidCheckPresent = false;
        boolean signTimeCheckPresent = false;
        boolean ctyCheckPresent = false;
        for (XmlConstraint xmlConstraint : xmlSAV.getConstraint()) {
            if (MessageTag.BBB_ICS_ISASCP.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                assertEquals(MessageTag.BBB_ICS_ISASCP_ANS.getId(), xmlConstraint.getError().getKey());
                signCertCheckPresent = true;
            } else if (MessageTag.BBB_ICS_ISASCPU.getId().equals(xmlConstraint.getName().getKey())) {
                signCertOnlyOneCheckPresent = true;
            } else if (MessageTag.BBB_ICS_ISAKIDP.getId().equals(xmlConstraint.getName().getKey())) {
                kidCheckPresent = true;
            } else if (MessageTag.BBB_SAV_ISQPSTP.getId().equals(xmlConstraint.getName().getKey())) {
                signTimeCheckPresent = true;
            } else if (MessageTag.BBB_SAV_ISQPCTP.getId().equals(xmlConstraint.getName().getKey())) {
                ctyCheckPresent = true;
            }
        }
        assertTrue(signCertCheckPresent);
        assertFalse(signCertOnlyOneCheckPresent);
        assertFalse(kidCheckPresent);
        assertFalse(signTimeCheckPresent);
        assertFalse(ctyCheckPresent);

        eu.europa.esig.dss.diagnostic.jaxb.XmlCertificate signingCertificate =
                tlsCertificateBindingSignature.getSigningCertificate().getCertificate();
        assertEquals(QWACProfile.QWAC_2, detailedReport.getCertificateQWACProfile(signingCertificate.getId()));

        eu.europa.esig.dss.detailedreport.jaxb.XmlSignature xmlSignature = detailedReport.getXmlSignatureById(tlsCertificateBindingSignature.getId());
        assertEquals(Indication.INDETERMINATE, xmlSignature.getConclusion().getIndication());
        assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, xmlSignature.getConclusion().getSubIndication());

        XmlValidationSignatureQualification signatureQualification = xmlSignature.getValidationSignatureQualification();
        assertEquals(SignatureQualification.NOT_ADES, signatureQualification.getSignatureQualification());

        XmlQWACProcess signatureQWACProcess = signatureQualification.getQWACProcess();
        assertEquals(signingCertificate.getId(), signatureQWACProcess.getId());
        assertEquals(QWACProfile.QWAC_2, signatureQWACProcess.getQWACType());
        assertEquals(Indication.PASSED, signatureQWACProcess.getConclusion().getIndication());

        // 2-qwac checks
        boolean certPolicyCheckPresent = false;
        boolean certQualConclusiveCheckPresent = false;
        boolean wsaCheckAtIssuanceTimePresent = false;
        boolean wsaCheckAtValidationTimePresent = false;
        boolean certValidityPeriodCheckPresent = false;
        boolean domainNamePresent = false;
        boolean extKeyUsageCheckPresent = false;
        boolean bbbCheckConclusive = false;
        boolean is2QWACProcessPresent = false;
        for (XmlValidationQWACProcess xmlValidationQWACProcess : signatureQWACProcess.getValidationQWACProcess()) {
            if (i18nProvider.getMessage(MessageTag.QWAC_VALIDATION_PROFILE,
                    ValidationProcessUtils.getQWACValidationMessageTag(QWACProfile.QWAC_2)).equals(xmlValidationQWACProcess.getTitle())) {
                assertEquals(Indication.PASSED, xmlValidationQWACProcess.getConclusion().getIndication());
                for (XmlConstraint xmlConstraint : xmlValidationQWACProcess.getConstraint()) {
                    if (MessageTag.QWAC_CERT_POLICY.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        certPolicyCheckPresent = true;
                    } else if (MessageTag.QWAC_CERT_QUAL_CONCLUSIVE.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        certQualConclusiveCheckPresent = true;
                    } else if (MessageTag.QWAC_IS_WSA_AT_TIME.getId().equals(xmlConstraint.getName().getKey())) {
                        if (i18nProvider.getMessage(MessageTag.QWAC_IS_WSA_AT_TIME, ValidationProcessUtils.getValidationTimeMessageTag(
                                ValidationTime.CERTIFICATE_ISSUANCE_TIME)).equals(xmlConstraint.getName().getValue())) {
                            assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                            wsaCheckAtIssuanceTimePresent = true;
                        } else if (i18nProvider.getMessage(MessageTag.QWAC_IS_WSA_AT_TIME, ValidationProcessUtils.getValidationTimeMessageTag(
                                ValidationTime.VALIDATION_TIME)).equals(xmlConstraint.getName().getValue())) {
                            assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                            wsaCheckAtValidationTimePresent = true;
                        }
                    } else if (MessageTag.QWAC_VAL_PERIOD.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        certValidityPeriodCheckPresent = true;
                    } else if (MessageTag.QWAC_DOMAIN_NAME.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        domainNamePresent = true;
                    } else if (MessageTag.QWAC2_EXT_KEY_USAGE.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        extKeyUsageCheckPresent = true;
                    } else if (MessageTag.BBB_ACCEPT.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        bbbCheckConclusive = true;
                    }
                }

                is2QWACProcessPresent = true;
            }
        }
        assertTrue(certPolicyCheckPresent);
        assertTrue(certQualConclusiveCheckPresent);
        assertTrue(wsaCheckAtIssuanceTimePresent);
        assertTrue(wsaCheckAtValidationTimePresent);
        assertTrue(certValidityPeriodCheckPresent);
        assertTrue(domainNamePresent);
        assertTrue(extKeyUsageCheckPresent);
        assertTrue(bbbCheckConclusive);
        assertTrue(is2QWACProcessPresent);

        checkReports(reports);
    }

    @Test
    void sigMultipleSignCertTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/qwac-validation/2-qwac-valid-diag-data.xml"));
        assertNotNull(diagnosticData);

        XmlTLSCertificateBindingSignature bindingSignature = diagnosticData.getConnectionInfo().getTLSCertificateBindingSignature();
        XmlFoundCertificates foundCertificates = bindingSignature.getSignature().getFoundCertificates();
        XmlRelatedCertificate xmlRelatedCertificate = new XmlRelatedCertificate();
        xmlRelatedCertificate.setCertificate(bindingSignature.getSignature().getSigningCertificate().getCertificate()
                .getSigningCertificate().getCertificate());
        XmlCertificateRef certificateRef = new XmlCertificateRef();
        certificateRef.setOrigin(CertificateRefOrigin.SIGNING_CERTIFICATE);
        certificateRef.setDigestAlgoAndValue(xmlRelatedCertificate.getCertificate().getDigestAlgoAndValue());
        xmlRelatedCertificate.getCertificateRefs().add(certificateRef);
        foundCertificates.getRelatedCertificates().add(xmlRelatedCertificate);

        String certificateId = "C-83D242F9A51C7A62BA1B774268EAAECBAB097479E83D8675C14F02DFB269FE77";

        QWACCertificateProcessExecutor executor = new QWACCertificateProcessExecutor();
        executor.setCertificateId(certificateId);
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        CertificateReports reports = executor.execute();

        SimpleCertificateReport simpleReport = reports.getSimpleReport();
        assertNotNull(simpleReport);

        assertEquals(QWACProfile.NOT_QWAC, simpleReport.getQWACProfile());
        assertEquals(QWACProfile.QWAC_2, simpleReport.getTLSBindingSignatureIssuerCertificateQWACProfile());

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(QWACProfile.NOT_QWAC, detailedReport.getCertificateQWACProfile(certificateId));

        XmlCertificate xmlCertificate = detailedReport.getXmlCertificateById(certificateId);
        assertNotNull(xmlCertificate);

        XmlQWACProcess qwacProcess = xmlCertificate.getQWACProcess();
        assertNotNull(qwacProcess);
        assertEquals(certificateId, qwacProcess.getId());
        assertEquals(QWACProfile.NOT_QWAC, qwacProcess.getQWACType());
        assertEquals(Indication.FAILED, qwacProcess.getConclusion().getIndication());

        boolean isQWACValidCheckFound = false;
        for (XmlConstraint xmlConstraint : qwacProcess.getConstraint()) {
            if (MessageTag.QWAC_VALID.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                assertEquals(MessageTag.QWAC_VALID_ANS.getId(), xmlConstraint.getError().getKey());
                isQWACValidCheckFound = true;
            }
        }
        assertTrue(isQWACValidCheckFound);

        // 1-qwac checks
        boolean is1QWACProcessPresent = false;
        boolean bbbCheckPresent = false;
        boolean qwac1DomainNamePresent = false;
        boolean linkHeaderPresent = false;
        boolean sigFormCheckPresent = false;
        boolean jadesCheckPresent = false;
        boolean jadesCompactCheckPresent = false;
        boolean expTimeCheckPresent = false;
        boolean sigExpCheckPresent = false;
        boolean qwac2CheckPresent = false;
        boolean sigValidCheckPresent = false;
        boolean tlsCertBindingValidCheckPresent = false;

        boolean isTlsSupportedBy2QWACProcessPresent = false;
        for (XmlValidationQWACProcess xmlValidationQWACProcess : qwacProcess.getValidationQWACProcess()) {
            if (i18nProvider.getMessage(MessageTag.QWAC_VALIDATION_PROFILE,
                    ValidationProcessUtils.getQWACValidationMessageTag(QWACProfile.QWAC_1)).equals(xmlValidationQWACProcess.getTitle())) {
                assertEquals(Indication.FAILED, xmlValidationQWACProcess.getConclusion().getIndication());
                is1QWACProcessPresent = true;

            } else if (i18nProvider.getMessage(MessageTag.QWAC_VALIDATION_PROFILE,
                    ValidationProcessUtils.getQWACValidationMessageTag(QWACProfile.TLS_BY_QWAC_2)).equals(xmlValidationQWACProcess.getTitle())) {
                assertEquals(Indication.FAILED, xmlValidationQWACProcess.getConclusion().getIndication());
                for (XmlConstraint xmlConstraint : xmlValidationQWACProcess.getConstraint()) {
                    if (MessageTag.BBB_ACCEPT.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        bbbCheckPresent = true;
                    } else if (MessageTag.QWAC_DOMAIN_NAME.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        qwac1DomainNamePresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_URL.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        linkHeaderPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        sigFormCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG_FORM.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        jadesCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG_SER.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        jadesCompactCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG_EXP.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        expTimeCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG_EXPIRY_DATE.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        sigExpCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_QWAC2.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        qwac2CheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG_VALID.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                        assertEquals(MessageTag.TLS_CERT_BINDING_SIG_VALID_ANS.getId(), xmlConstraint.getError().getKey());
                        sigValidCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_CERT_IDENTIFIED.getId().equals(xmlConstraint.getName().getKey())) {
                        tlsCertBindingValidCheckPresent = true;
                    }
                }

                isTlsSupportedBy2QWACProcessPresent = true;
            }
        }
        assertTrue(is1QWACProcessPresent);
        assertTrue(bbbCheckPresent);
        assertTrue(qwac1DomainNamePresent);
        assertTrue(linkHeaderPresent);
        assertTrue(sigFormCheckPresent);
        assertTrue(jadesCheckPresent);
        assertTrue(jadesCompactCheckPresent);
        assertTrue(expTimeCheckPresent);
        assertTrue(sigExpCheckPresent);
        assertTrue(qwac2CheckPresent);
        assertTrue(sigValidCheckPresent);
        assertFalse(tlsCertBindingValidCheckPresent);
        assertTrue(isTlsSupportedBy2QWACProcessPresent);

        XmlSignature tlsCertificateBindingSignature = diagnosticData
                .getConnectionInfo().getTLSCertificateBindingSignature().getSignature();

        XmlBasicBuildingBlocks sigBBB = detailedReport.getBasicBuildingBlockById(tlsCertificateBindingSignature.getId());
        assertNotNull(sigBBB);
        assertEquals(Indication.INDETERMINATE, sigBBB.getConclusion().getIndication());
        assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, sigBBB.getConclusion().getSubIndication());

        XmlSAV xmlSAV = sigBBB.getSAV();
        assertNotNull(xmlSAV);
        assertEquals(Indication.INDETERMINATE, xmlSAV.getConclusion().getIndication());
        assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, xmlSAV.getConclusion().getSubIndication());

        boolean signCertCheckPresent = false;
        boolean signCertOnlyOneCheckPresent = false;
        boolean kidCheckPresent = false;
        boolean signTimeCheckPresent = false;
        boolean ctyCheckPresent = false;
        for (XmlConstraint xmlConstraint : xmlSAV.getConstraint()) {
            if (MessageTag.BBB_ICS_ISASCP.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                signCertCheckPresent = true;
            } else if (MessageTag.BBB_ICS_ISASCPU.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                assertEquals(MessageTag.BBB_ICS_ISASCPU_ANS.getId(), xmlConstraint.getError().getKey());
                signCertOnlyOneCheckPresent = true;
            } else if (MessageTag.BBB_ICS_ISAKIDP.getId().equals(xmlConstraint.getName().getKey())) {
                kidCheckPresent = true;
            } else if (MessageTag.BBB_SAV_ISQPSTP.getId().equals(xmlConstraint.getName().getKey())) {
                signTimeCheckPresent = true;
            } else if (MessageTag.BBB_SAV_ISQPCTP.getId().equals(xmlConstraint.getName().getKey())) {
                ctyCheckPresent = true;
            }
        }
        assertTrue(signCertCheckPresent);
        assertTrue(signCertOnlyOneCheckPresent);
        assertFalse(kidCheckPresent);
        assertFalse(signTimeCheckPresent);
        assertFalse(ctyCheckPresent);

        eu.europa.esig.dss.diagnostic.jaxb.XmlCertificate signingCertificate =
                tlsCertificateBindingSignature.getSigningCertificate().getCertificate();
        assertEquals(QWACProfile.QWAC_2, detailedReport.getCertificateQWACProfile(signingCertificate.getId()));

        eu.europa.esig.dss.detailedreport.jaxb.XmlSignature xmlSignature = detailedReport.getXmlSignatureById(tlsCertificateBindingSignature.getId());
        assertEquals(Indication.INDETERMINATE, xmlSignature.getConclusion().getIndication());
        assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, xmlSignature.getConclusion().getSubIndication());

        XmlValidationSignatureQualification signatureQualification = xmlSignature.getValidationSignatureQualification();
        assertEquals(SignatureQualification.NOT_ADES, signatureQualification.getSignatureQualification());

        XmlQWACProcess signatureQWACProcess = signatureQualification.getQWACProcess();
        assertEquals(signingCertificate.getId(), signatureQWACProcess.getId());
        assertEquals(QWACProfile.QWAC_2, signatureQWACProcess.getQWACType());
        assertEquals(Indication.PASSED, signatureQWACProcess.getConclusion().getIndication());

        // 2-qwac checks
        boolean certPolicyCheckPresent = false;
        boolean certQualConclusiveCheckPresent = false;
        boolean wsaCheckAtIssuanceTimePresent = false;
        boolean wsaCheckAtValidationTimePresent = false;
        boolean certValidityPeriodCheckPresent = false;
        boolean domainNamePresent = false;
        boolean extKeyUsageCheckPresent = false;
        boolean bbbCheckConclusive = false;
        boolean is2QWACProcessPresent = false;
        for (XmlValidationQWACProcess xmlValidationQWACProcess : signatureQWACProcess.getValidationQWACProcess()) {
            if (i18nProvider.getMessage(MessageTag.QWAC_VALIDATION_PROFILE,
                    ValidationProcessUtils.getQWACValidationMessageTag(QWACProfile.QWAC_2)).equals(xmlValidationQWACProcess.getTitle())) {
                assertEquals(Indication.PASSED, xmlValidationQWACProcess.getConclusion().getIndication());
                for (XmlConstraint xmlConstraint : xmlValidationQWACProcess.getConstraint()) {
                    if (MessageTag.QWAC_CERT_POLICY.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        certPolicyCheckPresent = true;
                    } else if (MessageTag.QWAC_CERT_QUAL_CONCLUSIVE.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        certQualConclusiveCheckPresent = true;
                    } else if (MessageTag.QWAC_IS_WSA_AT_TIME.getId().equals(xmlConstraint.getName().getKey())) {
                        if (i18nProvider.getMessage(MessageTag.QWAC_IS_WSA_AT_TIME, ValidationProcessUtils.getValidationTimeMessageTag(
                                ValidationTime.CERTIFICATE_ISSUANCE_TIME)).equals(xmlConstraint.getName().getValue())) {
                            assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                            wsaCheckAtIssuanceTimePresent = true;
                        } else if (i18nProvider.getMessage(MessageTag.QWAC_IS_WSA_AT_TIME, ValidationProcessUtils.getValidationTimeMessageTag(
                                ValidationTime.VALIDATION_TIME)).equals(xmlConstraint.getName().getValue())) {
                            assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                            wsaCheckAtValidationTimePresent = true;
                        }
                    } else if (MessageTag.QWAC_VAL_PERIOD.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        certValidityPeriodCheckPresent = true;
                    } else if (MessageTag.QWAC_DOMAIN_NAME.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        domainNamePresent = true;
                    } else if (MessageTag.QWAC2_EXT_KEY_USAGE.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        extKeyUsageCheckPresent = true;
                    } else if (MessageTag.BBB_ACCEPT.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        bbbCheckConclusive = true;
                    }
                }

                is2QWACProcessPresent = true;
            }
        }
        assertTrue(certPolicyCheckPresent);
        assertTrue(certQualConclusiveCheckPresent);
        assertTrue(wsaCheckAtIssuanceTimePresent);
        assertTrue(wsaCheckAtValidationTimePresent);
        assertTrue(certValidityPeriodCheckPresent);
        assertTrue(domainNamePresent);
        assertTrue(extKeyUsageCheckPresent);
        assertTrue(bbbCheckConclusive);
        assertTrue(is2QWACProcessPresent);

        checkReports(reports);
    }

    @Test
    void sigKidNotPresentTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/qwac-validation/2-qwac-valid-diag-data.xml"));
        assertNotNull(diagnosticData);

        XmlTLSCertificateBindingSignature bindingSignature = diagnosticData.getConnectionInfo().getTLSCertificateBindingSignature();
        XmlFoundCertificates foundCertificates = bindingSignature.getSignature().getFoundCertificates();
        for (XmlRelatedCertificate xmlRelatedCertificate : foundCertificates.getRelatedCertificates()) {
            Iterator<XmlCertificateRef> it = xmlRelatedCertificate.getCertificateRefs().iterator();
            while (it.hasNext()) {
                XmlCertificateRef xmlCertificateRef = it.next();
                if (CertificateRefOrigin.KEY_IDENTIFIER == xmlCertificateRef.getOrigin()) {
                    it.remove();
                }
            }
        }

        String certificateId = "C-83D242F9A51C7A62BA1B774268EAAECBAB097479E83D8675C14F02DFB269FE77";

        QWACCertificateProcessExecutor executor = new QWACCertificateProcessExecutor();
        executor.setCertificateId(certificateId);
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        CertificateReports reports = executor.execute();

        SimpleCertificateReport simpleReport = reports.getSimpleReport();
        assertNotNull(simpleReport);

        assertEquals(QWACProfile.NOT_QWAC, simpleReport.getQWACProfile());
        assertEquals(QWACProfile.QWAC_2, simpleReport.getTLSBindingSignatureIssuerCertificateQWACProfile());

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(QWACProfile.NOT_QWAC, detailedReport.getCertificateQWACProfile(certificateId));

        XmlCertificate xmlCertificate = detailedReport.getXmlCertificateById(certificateId);
        assertNotNull(xmlCertificate);

        XmlQWACProcess qwacProcess = xmlCertificate.getQWACProcess();
        assertNotNull(qwacProcess);
        assertEquals(certificateId, qwacProcess.getId());
        assertEquals(QWACProfile.NOT_QWAC, qwacProcess.getQWACType());
        assertEquals(Indication.FAILED, qwacProcess.getConclusion().getIndication());

        boolean isQWACValidCheckFound = false;
        for (XmlConstraint xmlConstraint : qwacProcess.getConstraint()) {
            if (MessageTag.QWAC_VALID.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                assertEquals(MessageTag.QWAC_VALID_ANS.getId(), xmlConstraint.getError().getKey());
                isQWACValidCheckFound = true;
            }
        }
        assertTrue(isQWACValidCheckFound);

        // 1-qwac checks
        boolean is1QWACProcessPresent = false;
        boolean bbbCheckPresent = false;
        boolean qwac1DomainNamePresent = false;
        boolean linkHeaderPresent = false;
        boolean sigFormCheckPresent = false;
        boolean jadesCheckPresent = false;
        boolean jadesCompactCheckPresent = false;
        boolean expTimeCheckPresent = false;
        boolean sigExpCheckPresent = false;
        boolean qwac2CheckPresent = false;
        boolean sigValidCheckPresent = false;
        boolean tlsCertBindingValidCheckPresent = false;

        boolean isTlsSupportedBy2QWACProcessPresent = false;
        for (XmlValidationQWACProcess xmlValidationQWACProcess : qwacProcess.getValidationQWACProcess()) {
            if (i18nProvider.getMessage(MessageTag.QWAC_VALIDATION_PROFILE,
                    ValidationProcessUtils.getQWACValidationMessageTag(QWACProfile.QWAC_1)).equals(xmlValidationQWACProcess.getTitle())) {
                assertEquals(Indication.FAILED, xmlValidationQWACProcess.getConclusion().getIndication());
                is1QWACProcessPresent = true;

            } else if (i18nProvider.getMessage(MessageTag.QWAC_VALIDATION_PROFILE,
                    ValidationProcessUtils.getQWACValidationMessageTag(QWACProfile.TLS_BY_QWAC_2)).equals(xmlValidationQWACProcess.getTitle())) {
                assertEquals(Indication.FAILED, xmlValidationQWACProcess.getConclusion().getIndication());
                for (XmlConstraint xmlConstraint : xmlValidationQWACProcess.getConstraint()) {
                    if (MessageTag.BBB_ACCEPT.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        bbbCheckPresent = true;
                    } else if (MessageTag.QWAC_DOMAIN_NAME.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        qwac1DomainNamePresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_URL.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        linkHeaderPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        sigFormCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG_FORM.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        jadesCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG_SER.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        jadesCompactCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG_EXP.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        expTimeCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG_EXPIRY_DATE.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        sigExpCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_QWAC2.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        qwac2CheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG_VALID.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                        assertEquals(MessageTag.TLS_CERT_BINDING_SIG_VALID_ANS.getId(), xmlConstraint.getError().getKey());
                        sigValidCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_CERT_IDENTIFIED.getId().equals(xmlConstraint.getName().getKey())) {
                        tlsCertBindingValidCheckPresent = true;
                    }
                }

                isTlsSupportedBy2QWACProcessPresent = true;
            }
        }
        assertTrue(is1QWACProcessPresent);
        assertTrue(bbbCheckPresent);
        assertTrue(qwac1DomainNamePresent);
        assertTrue(linkHeaderPresent);
        assertTrue(sigFormCheckPresent);
        assertTrue(jadesCheckPresent);
        assertTrue(jadesCompactCheckPresent);
        assertTrue(expTimeCheckPresent);
        assertTrue(sigExpCheckPresent);
        assertTrue(qwac2CheckPresent);
        assertTrue(sigValidCheckPresent);
        assertFalse(tlsCertBindingValidCheckPresent);
        assertTrue(isTlsSupportedBy2QWACProcessPresent);

        XmlSignature tlsCertificateBindingSignature = diagnosticData
                .getConnectionInfo().getTLSCertificateBindingSignature().getSignature();

        XmlBasicBuildingBlocks sigBBB = detailedReport.getBasicBuildingBlockById(tlsCertificateBindingSignature.getId());
        assertNotNull(sigBBB);
        assertEquals(Indication.INDETERMINATE, sigBBB.getConclusion().getIndication());
        assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, sigBBB.getConclusion().getSubIndication());

        XmlSAV xmlSAV = sigBBB.getSAV();
        assertNotNull(xmlSAV);
        assertEquals(Indication.INDETERMINATE, xmlSAV.getConclusion().getIndication());
        assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, xmlSAV.getConclusion().getSubIndication());

        boolean signCertCheckPresent = false;
        boolean signCertOnlyOneCheckPresent = false;
        boolean kidCheckPresent = false;
        boolean signTimeCheckPresent = false;
        boolean ctyCheckPresent = false;
        for (XmlConstraint xmlConstraint : xmlSAV.getConstraint()) {
            if (MessageTag.BBB_ICS_ISASCP.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                signCertCheckPresent = true;
            } else if (MessageTag.BBB_ICS_ISASCPU.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                signCertOnlyOneCheckPresent = true;
            } else if (MessageTag.BBB_ICS_ISAKIDP.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                assertEquals(MessageTag.BBB_ICS_ISAKIDP_ANS.getId(), xmlConstraint.getError().getKey());
                kidCheckPresent = true;
            } else if (MessageTag.BBB_SAV_ISQPSTP.getId().equals(xmlConstraint.getName().getKey())) {
                signTimeCheckPresent = true;
            } else if (MessageTag.BBB_SAV_ISQPCTP.getId().equals(xmlConstraint.getName().getKey())) {
                ctyCheckPresent = true;
            }
        }
        assertTrue(signCertCheckPresent);
        assertTrue(signCertOnlyOneCheckPresent);
        assertTrue(kidCheckPresent);
        assertFalse(signTimeCheckPresent);
        assertFalse(ctyCheckPresent);

        eu.europa.esig.dss.diagnostic.jaxb.XmlCertificate signingCertificate =
                tlsCertificateBindingSignature.getSigningCertificate().getCertificate();
        assertEquals(QWACProfile.QWAC_2, detailedReport.getCertificateQWACProfile(signingCertificate.getId()));

        eu.europa.esig.dss.detailedreport.jaxb.XmlSignature xmlSignature = detailedReport.getXmlSignatureById(tlsCertificateBindingSignature.getId());
        assertEquals(Indication.INDETERMINATE, xmlSignature.getConclusion().getIndication());
        assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, xmlSignature.getConclusion().getSubIndication());

        XmlValidationSignatureQualification signatureQualification = xmlSignature.getValidationSignatureQualification();
        assertEquals(SignatureQualification.NOT_ADES, signatureQualification.getSignatureQualification());

        XmlQWACProcess signatureQWACProcess = signatureQualification.getQWACProcess();
        assertEquals(signingCertificate.getId(), signatureQWACProcess.getId());
        assertEquals(QWACProfile.QWAC_2, signatureQWACProcess.getQWACType());
        assertEquals(Indication.PASSED, signatureQWACProcess.getConclusion().getIndication());

        // 2-qwac checks
        boolean certPolicyCheckPresent = false;
        boolean certQualConclusiveCheckPresent = false;
        boolean wsaCheckAtIssuanceTimePresent = false;
        boolean wsaCheckAtValidationTimePresent = false;
        boolean certValidityPeriodCheckPresent = false;
        boolean domainNamePresent = false;
        boolean extKeyUsageCheckPresent = false;
        boolean bbbCheckConclusive = false;
        boolean is2QWACProcessPresent = false;
        for (XmlValidationQWACProcess xmlValidationQWACProcess : signatureQWACProcess.getValidationQWACProcess()) {
            if (i18nProvider.getMessage(MessageTag.QWAC_VALIDATION_PROFILE,
                    ValidationProcessUtils.getQWACValidationMessageTag(QWACProfile.QWAC_2)).equals(xmlValidationQWACProcess.getTitle())) {
                assertEquals(Indication.PASSED, xmlValidationQWACProcess.getConclusion().getIndication());
                for (XmlConstraint xmlConstraint : xmlValidationQWACProcess.getConstraint()) {
                    if (MessageTag.QWAC_CERT_POLICY.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        certPolicyCheckPresent = true;
                    } else if (MessageTag.QWAC_CERT_QUAL_CONCLUSIVE.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        certQualConclusiveCheckPresent = true;
                    } else if (MessageTag.QWAC_IS_WSA_AT_TIME.getId().equals(xmlConstraint.getName().getKey())) {
                        if (i18nProvider.getMessage(MessageTag.QWAC_IS_WSA_AT_TIME, ValidationProcessUtils.getValidationTimeMessageTag(
                                ValidationTime.CERTIFICATE_ISSUANCE_TIME)).equals(xmlConstraint.getName().getValue())) {
                            assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                            wsaCheckAtIssuanceTimePresent = true;
                        } else if (i18nProvider.getMessage(MessageTag.QWAC_IS_WSA_AT_TIME, ValidationProcessUtils.getValidationTimeMessageTag(
                                ValidationTime.VALIDATION_TIME)).equals(xmlConstraint.getName().getValue())) {
                            assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                            wsaCheckAtValidationTimePresent = true;
                        }
                    } else if (MessageTag.QWAC_VAL_PERIOD.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        certValidityPeriodCheckPresent = true;
                    } else if (MessageTag.QWAC_DOMAIN_NAME.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        domainNamePresent = true;
                    } else if (MessageTag.QWAC2_EXT_KEY_USAGE.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        extKeyUsageCheckPresent = true;
                    } else if (MessageTag.BBB_ACCEPT.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        bbbCheckConclusive = true;
                    }
                }

                is2QWACProcessPresent = true;
            }
        }
        assertTrue(certPolicyCheckPresent);
        assertTrue(certQualConclusiveCheckPresent);
        assertTrue(wsaCheckAtIssuanceTimePresent);
        assertTrue(wsaCheckAtValidationTimePresent);
        assertTrue(certValidityPeriodCheckPresent);
        assertTrue(domainNamePresent);
        assertTrue(extKeyUsageCheckPresent);
        assertTrue(bbbCheckConclusive);
        assertTrue(is2QWACProcessPresent);

        checkReports(reports);
    }

    @Test
    void sigNoSigTimeTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/qwac-validation/2-qwac-valid-diag-data.xml"));
        assertNotNull(diagnosticData);

        XmlTLSCertificateBindingSignature bindingSignature = diagnosticData.getConnectionInfo().getTLSCertificateBindingSignature();
        bindingSignature.getSignature().setClaimedSigningTime(null);

        String certificateId = "C-83D242F9A51C7A62BA1B774268EAAECBAB097479E83D8675C14F02DFB269FE77";

        QWACCertificateProcessExecutor executor = new QWACCertificateProcessExecutor();
        executor.setCertificateId(certificateId);
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        CertificateReports reports = executor.execute();

        SimpleCertificateReport simpleReport = reports.getSimpleReport();
        assertNotNull(simpleReport);

        assertEquals(QWACProfile.NOT_QWAC, simpleReport.getQWACProfile());
        assertEquals(QWACProfile.QWAC_2, simpleReport.getTLSBindingSignatureIssuerCertificateQWACProfile());

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(QWACProfile.NOT_QWAC, detailedReport.getCertificateQWACProfile(certificateId));

        XmlCertificate xmlCertificate = detailedReport.getXmlCertificateById(certificateId);
        assertNotNull(xmlCertificate);

        XmlQWACProcess qwacProcess = xmlCertificate.getQWACProcess();
        assertNotNull(qwacProcess);
        assertEquals(certificateId, qwacProcess.getId());
        assertEquals(QWACProfile.NOT_QWAC, qwacProcess.getQWACType());
        assertEquals(Indication.FAILED, qwacProcess.getConclusion().getIndication());

        boolean isQWACValidCheckFound = false;
        for (XmlConstraint xmlConstraint : qwacProcess.getConstraint()) {
            if (MessageTag.QWAC_VALID.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                assertEquals(MessageTag.QWAC_VALID_ANS.getId(), xmlConstraint.getError().getKey());
                isQWACValidCheckFound = true;
            }
        }
        assertTrue(isQWACValidCheckFound);

        // 1-qwac checks
        boolean is1QWACProcessPresent = false;
        boolean bbbCheckPresent = false;
        boolean qwac1DomainNamePresent = false;
        boolean linkHeaderPresent = false;
        boolean sigFormCheckPresent = false;
        boolean jadesCheckPresent = false;
        boolean jadesCompactCheckPresent = false;
        boolean expTimeCheckPresent = false;
        boolean sigExpCheckPresent = false;
        boolean qwac2CheckPresent = false;
        boolean sigValidCheckPresent = false;
        boolean tlsCertBindingValidCheckPresent = false;

        boolean isTlsSupportedBy2QWACProcessPresent = false;
        for (XmlValidationQWACProcess xmlValidationQWACProcess : qwacProcess.getValidationQWACProcess()) {
            if (i18nProvider.getMessage(MessageTag.QWAC_VALIDATION_PROFILE,
                    ValidationProcessUtils.getQWACValidationMessageTag(QWACProfile.QWAC_1)).equals(xmlValidationQWACProcess.getTitle())) {
                assertEquals(Indication.FAILED, xmlValidationQWACProcess.getConclusion().getIndication());
                is1QWACProcessPresent = true;

            } else if (i18nProvider.getMessage(MessageTag.QWAC_VALIDATION_PROFILE,
                    ValidationProcessUtils.getQWACValidationMessageTag(QWACProfile.TLS_BY_QWAC_2)).equals(xmlValidationQWACProcess.getTitle())) {
                assertEquals(Indication.FAILED, xmlValidationQWACProcess.getConclusion().getIndication());
                for (XmlConstraint xmlConstraint : xmlValidationQWACProcess.getConstraint()) {
                    if (MessageTag.BBB_ACCEPT.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        bbbCheckPresent = true;
                    } else if (MessageTag.QWAC_DOMAIN_NAME.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        qwac1DomainNamePresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_URL.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        linkHeaderPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        sigFormCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG_FORM.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        jadesCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG_SER.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        jadesCompactCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG_EXP.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        expTimeCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG_EXPIRY_DATE.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        sigExpCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_QWAC2.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        qwac2CheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG_VALID.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                        assertEquals(MessageTag.TLS_CERT_BINDING_SIG_VALID_ANS.getId(), xmlConstraint.getError().getKey());
                        sigValidCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_CERT_IDENTIFIED.getId().equals(xmlConstraint.getName().getKey())) {
                        tlsCertBindingValidCheckPresent = true;
                    }
                }

                isTlsSupportedBy2QWACProcessPresent = true;
            }
        }
        assertTrue(is1QWACProcessPresent);
        assertTrue(bbbCheckPresent);
        assertTrue(qwac1DomainNamePresent);
        assertTrue(linkHeaderPresent);
        assertTrue(sigFormCheckPresent);
        assertTrue(jadesCheckPresent);
        assertTrue(jadesCompactCheckPresent);
        assertTrue(expTimeCheckPresent);
        assertTrue(sigExpCheckPresent);
        assertTrue(qwac2CheckPresent);
        assertTrue(sigValidCheckPresent);
        assertFalse(tlsCertBindingValidCheckPresent);
        assertTrue(isTlsSupportedBy2QWACProcessPresent);

        XmlSignature tlsCertificateBindingSignature = diagnosticData
                .getConnectionInfo().getTLSCertificateBindingSignature().getSignature();

        XmlBasicBuildingBlocks sigBBB = detailedReport.getBasicBuildingBlockById(tlsCertificateBindingSignature.getId());
        assertNotNull(sigBBB);
        assertEquals(Indication.INDETERMINATE, sigBBB.getConclusion().getIndication());
        assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, sigBBB.getConclusion().getSubIndication());

        XmlSAV xmlSAV = sigBBB.getSAV();
        assertNotNull(xmlSAV);
        assertEquals(Indication.INDETERMINATE, xmlSAV.getConclusion().getIndication());
        assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, xmlSAV.getConclusion().getSubIndication());

        boolean signCertCheckPresent = false;
        boolean signCertOnlyOneCheckPresent = false;
        boolean kidCheckPresent = false;
        boolean signTimeCheckPresent = false;
        boolean ctyCheckPresent = false;
        for (XmlConstraint xmlConstraint : xmlSAV.getConstraint()) {
            if (MessageTag.BBB_ICS_ISASCP.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                signCertCheckPresent = true;
            } else if (MessageTag.BBB_ICS_ISASCPU.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                signCertOnlyOneCheckPresent = true;
            } else if (MessageTag.BBB_ICS_ISAKIDP.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                kidCheckPresent = true;
            } else if (MessageTag.BBB_SAV_ISQPSTP.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                assertEquals(MessageTag.BBB_SAV_ISQPSTP_ANS.getId(), xmlConstraint.getError().getKey());
                signTimeCheckPresent = true;
            } else if (MessageTag.BBB_SAV_ISQPCTP.getId().equals(xmlConstraint.getName().getKey())) {
                ctyCheckPresent = true;
            }
        }
        assertTrue(signCertCheckPresent);
        assertTrue(signCertOnlyOneCheckPresent);
        assertTrue(kidCheckPresent);
        assertTrue(signTimeCheckPresent);
        assertFalse(ctyCheckPresent);

        eu.europa.esig.dss.diagnostic.jaxb.XmlCertificate signingCertificate =
                tlsCertificateBindingSignature.getSigningCertificate().getCertificate();
        assertEquals(QWACProfile.QWAC_2, detailedReport.getCertificateQWACProfile(signingCertificate.getId()));

        eu.europa.esig.dss.detailedreport.jaxb.XmlSignature xmlSignature = detailedReport.getXmlSignatureById(tlsCertificateBindingSignature.getId());
        assertEquals(Indication.INDETERMINATE, xmlSignature.getConclusion().getIndication());
        assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, xmlSignature.getConclusion().getSubIndication());

        XmlValidationSignatureQualification signatureQualification = xmlSignature.getValidationSignatureQualification();
        assertEquals(SignatureQualification.NOT_ADES, signatureQualification.getSignatureQualification());

        XmlQWACProcess signatureQWACProcess = signatureQualification.getQWACProcess();
        assertEquals(signingCertificate.getId(), signatureQWACProcess.getId());
        assertEquals(QWACProfile.QWAC_2, signatureQWACProcess.getQWACType());
        assertEquals(Indication.PASSED, signatureQWACProcess.getConclusion().getIndication());

        // 2-qwac checks
        boolean certPolicyCheckPresent = false;
        boolean certQualConclusiveCheckPresent = false;
        boolean wsaCheckAtIssuanceTimePresent = false;
        boolean wsaCheckAtValidationTimePresent = false;
        boolean certValidityPeriodCheckPresent = false;
        boolean domainNamePresent = false;
        boolean extKeyUsageCheckPresent = false;
        boolean bbbCheckConclusive = false;
        boolean is2QWACProcessPresent = false;
        for (XmlValidationQWACProcess xmlValidationQWACProcess : signatureQWACProcess.getValidationQWACProcess()) {
            if (i18nProvider.getMessage(MessageTag.QWAC_VALIDATION_PROFILE,
                    ValidationProcessUtils.getQWACValidationMessageTag(QWACProfile.QWAC_2)).equals(xmlValidationQWACProcess.getTitle())) {
                assertEquals(Indication.PASSED, xmlValidationQWACProcess.getConclusion().getIndication());
                for (XmlConstraint xmlConstraint : xmlValidationQWACProcess.getConstraint()) {
                    if (MessageTag.QWAC_CERT_POLICY.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        certPolicyCheckPresent = true;
                    } else if (MessageTag.QWAC_CERT_QUAL_CONCLUSIVE.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        certQualConclusiveCheckPresent = true;
                    } else if (MessageTag.QWAC_IS_WSA_AT_TIME.getId().equals(xmlConstraint.getName().getKey())) {
                        if (i18nProvider.getMessage(MessageTag.QWAC_IS_WSA_AT_TIME, ValidationProcessUtils.getValidationTimeMessageTag(
                                ValidationTime.CERTIFICATE_ISSUANCE_TIME)).equals(xmlConstraint.getName().getValue())) {
                            assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                            wsaCheckAtIssuanceTimePresent = true;
                        } else if (i18nProvider.getMessage(MessageTag.QWAC_IS_WSA_AT_TIME, ValidationProcessUtils.getValidationTimeMessageTag(
                                ValidationTime.VALIDATION_TIME)).equals(xmlConstraint.getName().getValue())) {
                            assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                            wsaCheckAtValidationTimePresent = true;
                        }
                    } else if (MessageTag.QWAC_VAL_PERIOD.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        certValidityPeriodCheckPresent = true;
                    } else if (MessageTag.QWAC_DOMAIN_NAME.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        domainNamePresent = true;
                    } else if (MessageTag.QWAC2_EXT_KEY_USAGE.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        extKeyUsageCheckPresent = true;
                    } else if (MessageTag.BBB_ACCEPT.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        bbbCheckConclusive = true;
                    }
                }

                is2QWACProcessPresent = true;
            }
        }
        assertTrue(certPolicyCheckPresent);
        assertTrue(certQualConclusiveCheckPresent);
        assertTrue(wsaCheckAtIssuanceTimePresent);
        assertTrue(wsaCheckAtValidationTimePresent);
        assertTrue(certValidityPeriodCheckPresent);
        assertTrue(domainNamePresent);
        assertTrue(extKeyUsageCheckPresent);
        assertTrue(bbbCheckConclusive);
        assertTrue(is2QWACProcessPresent);

        checkReports(reports);
    }

    @Test
    void sigNoCtyTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/qwac-validation/2-qwac-valid-diag-data.xml"));
        assertNotNull(diagnosticData);

        XmlTLSCertificateBindingSignature bindingSignature = diagnosticData.getConnectionInfo().getTLSCertificateBindingSignature();
        bindingSignature.getSignature().setMimeType(null);

        String certificateId = "C-83D242F9A51C7A62BA1B774268EAAECBAB097479E83D8675C14F02DFB269FE77";

        QWACCertificateProcessExecutor executor = new QWACCertificateProcessExecutor();
        executor.setCertificateId(certificateId);
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        CertificateReports reports = executor.execute();

        SimpleCertificateReport simpleReport = reports.getSimpleReport();
        assertNotNull(simpleReport);

        assertEquals(QWACProfile.NOT_QWAC, simpleReport.getQWACProfile());
        assertEquals(QWACProfile.QWAC_2, simpleReport.getTLSBindingSignatureIssuerCertificateQWACProfile());

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(QWACProfile.NOT_QWAC, detailedReport.getCertificateQWACProfile(certificateId));

        XmlCertificate xmlCertificate = detailedReport.getXmlCertificateById(certificateId);
        assertNotNull(xmlCertificate);

        XmlQWACProcess qwacProcess = xmlCertificate.getQWACProcess();
        assertNotNull(qwacProcess);
        assertEquals(certificateId, qwacProcess.getId());
        assertEquals(QWACProfile.NOT_QWAC, qwacProcess.getQWACType());
        assertEquals(Indication.FAILED, qwacProcess.getConclusion().getIndication());

        boolean isQWACValidCheckFound = false;
        for (XmlConstraint xmlConstraint : qwacProcess.getConstraint()) {
            if (MessageTag.QWAC_VALID.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                assertEquals(MessageTag.QWAC_VALID_ANS.getId(), xmlConstraint.getError().getKey());
                isQWACValidCheckFound = true;
            }
        }
        assertTrue(isQWACValidCheckFound);

        // 1-qwac checks
        boolean is1QWACProcessPresent = false;
        boolean bbbCheckPresent = false;
        boolean qwac1DomainNamePresent = false;
        boolean linkHeaderPresent = false;
        boolean sigFormCheckPresent = false;
        boolean jadesCheckPresent = false;
        boolean jadesCompactCheckPresent = false;
        boolean expTimeCheckPresent = false;
        boolean sigExpCheckPresent = false;
        boolean qwac2CheckPresent = false;
        boolean sigValidCheckPresent = false;
        boolean tlsCertBindingValidCheckPresent = false;

        boolean isTlsSupportedBy2QWACProcessPresent = false;
        for (XmlValidationQWACProcess xmlValidationQWACProcess : qwacProcess.getValidationQWACProcess()) {
            if (i18nProvider.getMessage(MessageTag.QWAC_VALIDATION_PROFILE,
                    ValidationProcessUtils.getQWACValidationMessageTag(QWACProfile.QWAC_1)).equals(xmlValidationQWACProcess.getTitle())) {
                assertEquals(Indication.FAILED, xmlValidationQWACProcess.getConclusion().getIndication());
                is1QWACProcessPresent = true;

            } else if (i18nProvider.getMessage(MessageTag.QWAC_VALIDATION_PROFILE,
                    ValidationProcessUtils.getQWACValidationMessageTag(QWACProfile.TLS_BY_QWAC_2)).equals(xmlValidationQWACProcess.getTitle())) {
                assertEquals(Indication.FAILED, xmlValidationQWACProcess.getConclusion().getIndication());
                for (XmlConstraint xmlConstraint : xmlValidationQWACProcess.getConstraint()) {
                    if (MessageTag.BBB_ACCEPT.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        bbbCheckPresent = true;
                    } else if (MessageTag.QWAC_DOMAIN_NAME.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        qwac1DomainNamePresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_URL.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        linkHeaderPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        sigFormCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG_FORM.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        jadesCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG_SER.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        jadesCompactCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG_EXP.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        expTimeCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG_EXPIRY_DATE.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        sigExpCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_QWAC2.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        qwac2CheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG_VALID.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                        assertEquals(MessageTag.TLS_CERT_BINDING_SIG_VALID_ANS.getId(), xmlConstraint.getError().getKey());
                        sigValidCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_CERT_IDENTIFIED.getId().equals(xmlConstraint.getName().getKey())) {
                        tlsCertBindingValidCheckPresent = true;
                    }
                }

                isTlsSupportedBy2QWACProcessPresent = true;
            }
        }
        assertTrue(is1QWACProcessPresent);
        assertTrue(bbbCheckPresent);
        assertTrue(qwac1DomainNamePresent);
        assertTrue(linkHeaderPresent);
        assertTrue(sigFormCheckPresent);
        assertTrue(jadesCheckPresent);
        assertTrue(jadesCompactCheckPresent);
        assertTrue(expTimeCheckPresent);
        assertTrue(sigExpCheckPresent);
        assertTrue(qwac2CheckPresent);
        assertTrue(sigValidCheckPresent);
        assertFalse(tlsCertBindingValidCheckPresent);
        assertTrue(isTlsSupportedBy2QWACProcessPresent);

        XmlSignature tlsCertificateBindingSignature = diagnosticData
                .getConnectionInfo().getTLSCertificateBindingSignature().getSignature();

        XmlBasicBuildingBlocks sigBBB = detailedReport.getBasicBuildingBlockById(tlsCertificateBindingSignature.getId());
        assertNotNull(sigBBB);
        assertEquals(Indication.INDETERMINATE, sigBBB.getConclusion().getIndication());
        assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, sigBBB.getConclusion().getSubIndication());

        XmlSAV xmlSAV = sigBBB.getSAV();
        assertNotNull(xmlSAV);
        assertEquals(Indication.INDETERMINATE, xmlSAV.getConclusion().getIndication());
        assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, xmlSAV.getConclusion().getSubIndication());

        boolean signCertCheckPresent = false;
        boolean signCertOnlyOneCheckPresent = false;
        boolean kidCheckPresent = false;
        boolean signTimeCheckPresent = false;
        boolean ctyCheckPresent = false;
        for (XmlConstraint xmlConstraint : xmlSAV.getConstraint()) {
            if (MessageTag.BBB_ICS_ISASCP.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                signCertCheckPresent = true;
            } else if (MessageTag.BBB_ICS_ISASCPU.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                signCertOnlyOneCheckPresent = true;
            } else if (MessageTag.BBB_ICS_ISAKIDP.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                kidCheckPresent = true;
            } else if (MessageTag.BBB_SAV_ISQPSTP.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                signTimeCheckPresent = true;
            } else if (MessageTag.BBB_SAV_ISQPCTP.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                assertEquals(MessageTag.BBB_SAV_ISQPCTP_ANS.getId(), xmlConstraint.getError().getKey());
                ctyCheckPresent = true;
            }
        }
        assertTrue(signCertCheckPresent);
        assertTrue(signCertOnlyOneCheckPresent);
        assertTrue(kidCheckPresent);
        assertTrue(signTimeCheckPresent);
        assertTrue(ctyCheckPresent);

        eu.europa.esig.dss.diagnostic.jaxb.XmlCertificate signingCertificate =
                tlsCertificateBindingSignature.getSigningCertificate().getCertificate();
        assertEquals(QWACProfile.QWAC_2, detailedReport.getCertificateQWACProfile(signingCertificate.getId()));

        eu.europa.esig.dss.detailedreport.jaxb.XmlSignature xmlSignature = detailedReport.getXmlSignatureById(tlsCertificateBindingSignature.getId());
        assertEquals(Indication.INDETERMINATE, xmlSignature.getConclusion().getIndication());
        assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, xmlSignature.getConclusion().getSubIndication());

        XmlValidationSignatureQualification signatureQualification = xmlSignature.getValidationSignatureQualification();
        assertEquals(SignatureQualification.NOT_ADES, signatureQualification.getSignatureQualification());

        XmlQWACProcess signatureQWACProcess = signatureQualification.getQWACProcess();
        assertEquals(signingCertificate.getId(), signatureQWACProcess.getId());
        assertEquals(QWACProfile.QWAC_2, signatureQWACProcess.getQWACType());
        assertEquals(Indication.PASSED, signatureQWACProcess.getConclusion().getIndication());

        // 2-qwac checks
        boolean certPolicyCheckPresent = false;
        boolean certQualConclusiveCheckPresent = false;
        boolean wsaCheckAtIssuanceTimePresent = false;
        boolean wsaCheckAtValidationTimePresent = false;
        boolean certValidityPeriodCheckPresent = false;
        boolean domainNamePresent = false;
        boolean extKeyUsageCheckPresent = false;
        boolean bbbCheckConclusive = false;
        boolean is2QWACProcessPresent = false;
        for (XmlValidationQWACProcess xmlValidationQWACProcess : signatureQWACProcess.getValidationQWACProcess()) {
            if (i18nProvider.getMessage(MessageTag.QWAC_VALIDATION_PROFILE,
                    ValidationProcessUtils.getQWACValidationMessageTag(QWACProfile.QWAC_2)).equals(xmlValidationQWACProcess.getTitle())) {
                assertEquals(Indication.PASSED, xmlValidationQWACProcess.getConclusion().getIndication());
                for (XmlConstraint xmlConstraint : xmlValidationQWACProcess.getConstraint()) {
                    if (MessageTag.QWAC_CERT_POLICY.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        certPolicyCheckPresent = true;
                    } else if (MessageTag.QWAC_CERT_QUAL_CONCLUSIVE.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        certQualConclusiveCheckPresent = true;
                    } else if (MessageTag.QWAC_IS_WSA_AT_TIME.getId().equals(xmlConstraint.getName().getKey())) {
                        if (i18nProvider.getMessage(MessageTag.QWAC_IS_WSA_AT_TIME, ValidationProcessUtils.getValidationTimeMessageTag(
                                ValidationTime.CERTIFICATE_ISSUANCE_TIME)).equals(xmlConstraint.getName().getValue())) {
                            assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                            wsaCheckAtIssuanceTimePresent = true;
                        } else if (i18nProvider.getMessage(MessageTag.QWAC_IS_WSA_AT_TIME, ValidationProcessUtils.getValidationTimeMessageTag(
                                ValidationTime.VALIDATION_TIME)).equals(xmlConstraint.getName().getValue())) {
                            assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                            wsaCheckAtValidationTimePresent = true;
                        }
                    } else if (MessageTag.QWAC_VAL_PERIOD.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        certValidityPeriodCheckPresent = true;
                    } else if (MessageTag.QWAC_DOMAIN_NAME.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        domainNamePresent = true;
                    } else if (MessageTag.QWAC2_EXT_KEY_USAGE.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        extKeyUsageCheckPresent = true;
                    } else if (MessageTag.BBB_ACCEPT.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        bbbCheckConclusive = true;
                    }
                }

                is2QWACProcessPresent = true;
            }
        }
        assertTrue(certPolicyCheckPresent);
        assertTrue(certQualConclusiveCheckPresent);
        assertTrue(wsaCheckAtIssuanceTimePresent);
        assertTrue(wsaCheckAtValidationTimePresent);
        assertTrue(certValidityPeriodCheckPresent);
        assertTrue(domainNamePresent);
        assertTrue(extKeyUsageCheckPresent);
        assertTrue(bbbCheckConclusive);
        assertTrue(is2QWACProcessPresent);

        checkReports(reports);
    }

    @Test
    void tlsCertRevokedTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/qwac-validation/2-qwac-valid-diag-data.xml"));
        assertNotNull(diagnosticData);

        String certificateId = "C-83D242F9A51C7A62BA1B774268EAAECBAB097479E83D8675C14F02DFB269FE77";

        for (eu.europa.esig.dss.diagnostic.jaxb.XmlCertificate xmlCertificate : diagnosticData.getUsedCertificates()) {
            if (certificateId.equals(xmlCertificate.getId())) {
                List<XmlCertificateRevocation> revocations = xmlCertificate.getRevocations();
                XmlCertificateRevocation xmlCertificateRevocation = revocations.get(0);
                xmlCertificateRevocation.setStatus(CertificateStatus.REVOKED);
                xmlCertificateRevocation.setReason(RevocationReason.SUPERSEDED);
                Calendar calendar = Calendar.getInstance();
                calendar.setTime(diagnosticData.getValidationDate());
                calendar.add(Calendar.MONTH, -1);
                xmlCertificateRevocation.setRevocationDate(calendar.getTime());
            }
        }

        QWACCertificateProcessExecutor executor = new QWACCertificateProcessExecutor();
        executor.setCertificateId(certificateId);
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        CertificateReports reports = executor.execute();

        SimpleCertificateReport simpleReport = reports.getSimpleReport();
        assertNotNull(simpleReport);

        assertEquals(QWACProfile.NOT_QWAC, simpleReport.getQWACProfile());
        assertEquals(QWACProfile.QWAC_2, simpleReport.getTLSBindingSignatureIssuerCertificateQWACProfile());

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(QWACProfile.NOT_QWAC, detailedReport.getCertificateQWACProfile(certificateId));

        XmlCertificate xmlCertificate = detailedReport.getXmlCertificateById(certificateId);
        assertNotNull(xmlCertificate);

        XmlQWACProcess qwacProcess = xmlCertificate.getQWACProcess();
        assertNotNull(qwacProcess);
        assertEquals(certificateId, qwacProcess.getId());
        assertEquals(QWACProfile.NOT_QWAC, qwacProcess.getQWACType());
        assertEquals(Indication.FAILED, qwacProcess.getConclusion().getIndication());

        boolean isQWACValidCheckFound = false;
        for (XmlConstraint xmlConstraint : qwacProcess.getConstraint()) {
            if (MessageTag.QWAC_VALID.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                assertEquals(MessageTag.QWAC_VALID_ANS.getId(), xmlConstraint.getError().getKey());
                isQWACValidCheckFound = true;
            }
        }
        assertTrue(isQWACValidCheckFound);

        // 1-qwac checks
        boolean is1QWACProcessPresent = false;
        boolean bbbCheckPresent = false;
        boolean qwac1DomainNamePresent = false;
        boolean linkHeaderPresent = false;
        boolean sigFormCheckPresent = false;
        boolean jadesCheckPresent = false;
        boolean jadesCompactCheckPresent = false;
        boolean expTimeCheckPresent = false;
        boolean sigExpCheckPresent = false;
        boolean qwac2CheckPresent = false;
        boolean sigValidCheckPresent = false;
        boolean tlsCertBindingValidCheckPresent = false;

        boolean isTlsSupportedBy2QWACProcessPresent = false;
        for (XmlValidationQWACProcess xmlValidationQWACProcess : qwacProcess.getValidationQWACProcess()) {
            if (i18nProvider.getMessage(MessageTag.QWAC_VALIDATION_PROFILE,
                    ValidationProcessUtils.getQWACValidationMessageTag(QWACProfile.QWAC_1)).equals(xmlValidationQWACProcess.getTitle())) {
                assertEquals(Indication.FAILED, xmlValidationQWACProcess.getConclusion().getIndication());
                is1QWACProcessPresent = true;

            } else if (i18nProvider.getMessage(MessageTag.QWAC_VALIDATION_PROFILE,
                    ValidationProcessUtils.getQWACValidationMessageTag(QWACProfile.TLS_BY_QWAC_2)).equals(xmlValidationQWACProcess.getTitle())) {
                assertEquals(Indication.INDETERMINATE, xmlValidationQWACProcess.getConclusion().getIndication());
                for (XmlConstraint xmlConstraint : xmlValidationQWACProcess.getConstraint()) {
                    if (MessageTag.BBB_ACCEPT.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                        assertEquals(MessageTag.BBB_ACCEPT_ANS.getId(), xmlConstraint.getError().getKey());
                        bbbCheckPresent = true;
                    } else if (MessageTag.QWAC_DOMAIN_NAME.getId().equals(xmlConstraint.getName().getKey())) {
                        qwac1DomainNamePresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_URL.getId().equals(xmlConstraint.getName().getKey())) {
                        linkHeaderPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG.getId().equals(xmlConstraint.getName().getKey())) {
                        sigFormCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG_FORM.getId().equals(xmlConstraint.getName().getKey())) {
                        jadesCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG_SER.getId().equals(xmlConstraint.getName().getKey())) {
                        jadesCompactCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG_EXP.getId().equals(xmlConstraint.getName().getKey())) {
                        expTimeCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG_EXPIRY_DATE.getId().equals(xmlConstraint.getName().getKey())) {
                        sigExpCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_QWAC2.getId().equals(xmlConstraint.getName().getKey())) {
                        qwac2CheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG_VALID.getId().equals(xmlConstraint.getName().getKey())) {
                        sigValidCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_CERT_IDENTIFIED.getId().equals(xmlConstraint.getName().getKey())) {
                        tlsCertBindingValidCheckPresent = true;
                    }
                }

                isTlsSupportedBy2QWACProcessPresent = true;
            }
        }
        assertTrue(is1QWACProcessPresent);
        assertTrue(bbbCheckPresent);
        assertFalse(qwac1DomainNamePresent);
        assertFalse(linkHeaderPresent);
        assertFalse(sigFormCheckPresent);
        assertFalse(jadesCheckPresent);
        assertFalse(jadesCompactCheckPresent);
        assertFalse(expTimeCheckPresent);
        assertFalse(sigExpCheckPresent);
        assertFalse(qwac2CheckPresent);
        assertFalse(sigValidCheckPresent);
        assertFalse(tlsCertBindingValidCheckPresent);
        assertTrue(isTlsSupportedBy2QWACProcessPresent);

        XmlSignature tlsCertificateBindingSignature = diagnosticData
                .getConnectionInfo().getTLSCertificateBindingSignature().getSignature();

        XmlBasicBuildingBlocks sigBBB = detailedReport.getBasicBuildingBlockById(tlsCertificateBindingSignature.getId());
        assertNotNull(sigBBB);
        assertEquals(Indication.PASSED, sigBBB.getConclusion().getIndication());

        XmlSAV xmlSAV = sigBBB.getSAV();
        assertNotNull(xmlSAV);
        assertEquals(Indication.PASSED, xmlSAV.getConclusion().getIndication());

        boolean signCertCheckPresent = false;
        boolean signCertOnlyOneCheckPresent = false;
        boolean kidCheckPresent = false;
        boolean signTimeCheckPresent = false;
        boolean ctyCheckPresent = false;
        for (XmlConstraint xmlConstraint : xmlSAV.getConstraint()) {
            assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
            if (MessageTag.BBB_ICS_ISASCP.getId().equals(xmlConstraint.getName().getKey())) {
                signCertCheckPresent = true;
            } else if (MessageTag.BBB_ICS_ISASCPU.getId().equals(xmlConstraint.getName().getKey())) {
                signCertOnlyOneCheckPresent = true;
            } else if (MessageTag.BBB_ICS_ISAKIDP.getId().equals(xmlConstraint.getName().getKey())) {
                kidCheckPresent = true;
            } else if (MessageTag.BBB_SAV_ISQPSTP.getId().equals(xmlConstraint.getName().getKey())) {
                signTimeCheckPresent = true;
            } else if (MessageTag.BBB_SAV_ISQPCTP.getId().equals(xmlConstraint.getName().getKey())) {
                ctyCheckPresent = true;
            }
        }
        assertTrue(signCertCheckPresent);
        assertTrue(signCertOnlyOneCheckPresent);
        assertTrue(kidCheckPresent);
        assertTrue(signTimeCheckPresent);
        assertTrue(ctyCheckPresent);

        eu.europa.esig.dss.diagnostic.jaxb.XmlCertificate signingCertificate =
                tlsCertificateBindingSignature.getSigningCertificate().getCertificate();
        assertEquals(QWACProfile.QWAC_2, detailedReport.getCertificateQWACProfile(signingCertificate.getId()));

        eu.europa.esig.dss.detailedreport.jaxb.XmlSignature xmlSignature = detailedReport.getXmlSignatureById(tlsCertificateBindingSignature.getId());
        assertEquals(Indication.TOTAL_PASSED, xmlSignature.getConclusion().getIndication());

        XmlValidationSignatureQualification signatureQualification = xmlSignature.getValidationSignatureQualification();
        assertEquals(SignatureQualification.NOT_ADES, signatureQualification.getSignatureQualification());

        XmlQWACProcess signatureQWACProcess = signatureQualification.getQWACProcess();
        assertEquals(signingCertificate.getId(), signatureQWACProcess.getId());
        assertEquals(QWACProfile.QWAC_2, signatureQWACProcess.getQWACType());
        assertEquals(Indication.PASSED, signatureQWACProcess.getConclusion().getIndication());

        // 2-qwac checks
        boolean certPolicyCheckPresent = false;
        boolean certQualConclusiveCheckPresent = false;
        boolean wsaCheckAtIssuanceTimePresent = false;
        boolean wsaCheckAtValidationTimePresent = false;
        boolean certValidityPeriodCheckPresent = false;
        boolean domainNamePresent = false;
        boolean extKeyUsageCheckPresent = false;
        boolean bbbCheckConclusive = false;
        boolean is2QWACProcessPresent = false;
        for (XmlValidationQWACProcess xmlValidationQWACProcess : signatureQWACProcess.getValidationQWACProcess()) {
            if (i18nProvider.getMessage(MessageTag.QWAC_VALIDATION_PROFILE,
                    ValidationProcessUtils.getQWACValidationMessageTag(QWACProfile.QWAC_2)).equals(xmlValidationQWACProcess.getTitle())) {
                assertEquals(Indication.PASSED, xmlValidationQWACProcess.getConclusion().getIndication());
                for (XmlConstraint xmlConstraint : xmlValidationQWACProcess.getConstraint()) {
                    assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                    if (MessageTag.QWAC_CERT_POLICY.getId().equals(xmlConstraint.getName().getKey())) {
                        certPolicyCheckPresent = true;
                    } else if (MessageTag.QWAC_CERT_QUAL_CONCLUSIVE.getId().equals(xmlConstraint.getName().getKey())) {
                        certQualConclusiveCheckPresent = true;
                    } else if (MessageTag.QWAC_IS_WSA_AT_TIME.getId().equals(xmlConstraint.getName().getKey())) {
                        if (i18nProvider.getMessage(MessageTag.QWAC_IS_WSA_AT_TIME, ValidationProcessUtils.getValidationTimeMessageTag(
                                ValidationTime.CERTIFICATE_ISSUANCE_TIME)).equals(xmlConstraint.getName().getValue())) {
                            wsaCheckAtIssuanceTimePresent = true;
                        } else if (i18nProvider.getMessage(MessageTag.QWAC_IS_WSA_AT_TIME, ValidationProcessUtils.getValidationTimeMessageTag(
                                ValidationTime.VALIDATION_TIME)).equals(xmlConstraint.getName().getValue())) {
                            wsaCheckAtValidationTimePresent = true;
                        }
                    } else if (MessageTag.QWAC_VAL_PERIOD.getId().equals(xmlConstraint.getName().getKey())) {
                        certValidityPeriodCheckPresent = true;
                    } else if (MessageTag.QWAC_DOMAIN_NAME.getId().equals(xmlConstraint.getName().getKey())) {
                        domainNamePresent = true;
                    } else if (MessageTag.QWAC2_EXT_KEY_USAGE.getId().equals(xmlConstraint.getName().getKey())) {
                        extKeyUsageCheckPresent = true;
                    } else if (MessageTag.BBB_ACCEPT.getId().equals(xmlConstraint.getName().getKey())) {
                        bbbCheckConclusive = true;
                    }
                }

                is2QWACProcessPresent = true;
            }
        }
        assertTrue(certPolicyCheckPresent);
        assertTrue(certQualConclusiveCheckPresent);
        assertTrue(wsaCheckAtIssuanceTimePresent);
        assertTrue(wsaCheckAtValidationTimePresent);
        assertTrue(certValidityPeriodCheckPresent);
        assertTrue(domainNamePresent);
        assertTrue(extKeyUsageCheckPresent);
        assertTrue(bbbCheckConclusive);
        assertTrue(is2QWACProcessPresent);

        checkReports(reports);
    }

    @Test
    void tlsWrongDomainNameTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/qwac-validation/2-qwac-valid-diag-data.xml"));
        assertNotNull(diagnosticData);

        String certificateId = "C-83D242F9A51C7A62BA1B774268EAAECBAB097479E83D8675C14F02DFB269FE77";

        for (eu.europa.esig.dss.diagnostic.jaxb.XmlCertificate xmlCertificate : diagnosticData.getUsedCertificates()) {
            if (certificateId.equals(xmlCertificate.getId())) {
                for (XmlCertificateExtension certificateExtension : xmlCertificate.getCertificateExtensions()) {
                    if (CertificateExtensionEnum.SUBJECT_ALTERNATIVE_NAME.getOid().equals(certificateExtension.getOID())) {
                        XmlSubjectAlternativeNames xmlSubjectAlternativeNames = (XmlSubjectAlternativeNames) certificateExtension;
                        XmlGeneralName xmlGeneralName = new XmlGeneralName();
                        xmlGeneralName.setType(GeneralNameType.DNS_NAME);
                        xmlGeneralName.setValue("wikipedia.com");
                        xmlSubjectAlternativeNames.getSubjectAlternativeName().clear();
                        xmlSubjectAlternativeNames.getSubjectAlternativeName().add(xmlGeneralName);
                    }
                }
            }
        }

        QWACCertificateProcessExecutor executor = new QWACCertificateProcessExecutor();
        executor.setCertificateId(certificateId);
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        CertificateReports reports = executor.execute();

        SimpleCertificateReport simpleReport = reports.getSimpleReport();
        assertNotNull(simpleReport);

        assertEquals(QWACProfile.NOT_QWAC, simpleReport.getQWACProfile());
        assertEquals(QWACProfile.QWAC_2, simpleReport.getTLSBindingSignatureIssuerCertificateQWACProfile());

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(QWACProfile.NOT_QWAC, detailedReport.getCertificateQWACProfile(certificateId));

        XmlCertificate xmlCertificate = detailedReport.getXmlCertificateById(certificateId);
        assertNotNull(xmlCertificate);

        XmlQWACProcess qwacProcess = xmlCertificate.getQWACProcess();
        assertNotNull(qwacProcess);
        assertEquals(certificateId, qwacProcess.getId());
        assertEquals(QWACProfile.NOT_QWAC, qwacProcess.getQWACType());
        assertEquals(Indication.FAILED, qwacProcess.getConclusion().getIndication());

        boolean isQWACValidCheckFound = false;
        for (XmlConstraint xmlConstraint : qwacProcess.getConstraint()) {
            if (MessageTag.QWAC_VALID.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                assertEquals(MessageTag.QWAC_VALID_ANS.getId(), xmlConstraint.getError().getKey());
                isQWACValidCheckFound = true;
            }
        }
        assertTrue(isQWACValidCheckFound);

        // 1-qwac checks
        boolean is1QWACProcessPresent = false;
        boolean bbbCheckPresent = false;
        boolean qwac1DomainNamePresent = false;
        boolean linkHeaderPresent = false;
        boolean sigFormCheckPresent = false;
        boolean jadesCheckPresent = false;
        boolean jadesCompactCheckPresent = false;
        boolean expTimeCheckPresent = false;
        boolean sigExpCheckPresent = false;
        boolean qwac2CheckPresent = false;
        boolean sigValidCheckPresent = false;
        boolean tlsCertBindingValidCheckPresent = false;

        boolean isTlsSupportedBy2QWACProcessPresent = false;
        for (XmlValidationQWACProcess xmlValidationQWACProcess : qwacProcess.getValidationQWACProcess()) {
            if (i18nProvider.getMessage(MessageTag.QWAC_VALIDATION_PROFILE,
                    ValidationProcessUtils.getQWACValidationMessageTag(QWACProfile.QWAC_1)).equals(xmlValidationQWACProcess.getTitle())) {
                assertEquals(Indication.FAILED, xmlValidationQWACProcess.getConclusion().getIndication());
                is1QWACProcessPresent = true;

            } else if (i18nProvider.getMessage(MessageTag.QWAC_VALIDATION_PROFILE,
                    ValidationProcessUtils.getQWACValidationMessageTag(QWACProfile.TLS_BY_QWAC_2)).equals(xmlValidationQWACProcess.getTitle())) {
                assertEquals(Indication.FAILED, xmlValidationQWACProcess.getConclusion().getIndication());
                for (XmlConstraint xmlConstraint : xmlValidationQWACProcess.getConstraint()) {
                    if (MessageTag.BBB_ACCEPT.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        bbbCheckPresent = true;
                    } else if (MessageTag.QWAC_DOMAIN_NAME.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                        assertEquals(MessageTag.QWAC_DOMAIN_NAME_ANS.getId(), xmlConstraint.getError().getKey());
                        qwac1DomainNamePresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_URL.getId().equals(xmlConstraint.getName().getKey())) {
                        linkHeaderPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG.getId().equals(xmlConstraint.getName().getKey())) {
                        sigFormCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG_FORM.getId().equals(xmlConstraint.getName().getKey())) {
                        jadesCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG_SER.getId().equals(xmlConstraint.getName().getKey())) {
                        jadesCompactCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG_EXP.getId().equals(xmlConstraint.getName().getKey())) {
                        expTimeCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG_EXPIRY_DATE.getId().equals(xmlConstraint.getName().getKey())) {
                        sigExpCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_QWAC2.getId().equals(xmlConstraint.getName().getKey())) {
                        qwac2CheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG_VALID.getId().equals(xmlConstraint.getName().getKey())) {
                        sigValidCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_CERT_IDENTIFIED.getId().equals(xmlConstraint.getName().getKey())) {
                        tlsCertBindingValidCheckPresent = true;
                    }
                }

                isTlsSupportedBy2QWACProcessPresent = true;
            }
        }
        assertTrue(is1QWACProcessPresent);
        assertTrue(bbbCheckPresent);
        assertTrue(qwac1DomainNamePresent);
        assertFalse(linkHeaderPresent);
        assertFalse(sigFormCheckPresent);
        assertFalse(jadesCheckPresent);
        assertFalse(jadesCompactCheckPresent);
        assertFalse(expTimeCheckPresent);
        assertFalse(sigExpCheckPresent);
        assertFalse(qwac2CheckPresent);
        assertFalse(sigValidCheckPresent);
        assertFalse(tlsCertBindingValidCheckPresent);
        assertTrue(isTlsSupportedBy2QWACProcessPresent);

        XmlSignature tlsCertificateBindingSignature = diagnosticData
                .getConnectionInfo().getTLSCertificateBindingSignature().getSignature();

        XmlBasicBuildingBlocks sigBBB = detailedReport.getBasicBuildingBlockById(tlsCertificateBindingSignature.getId());
        assertNotNull(sigBBB);
        assertEquals(Indication.PASSED, sigBBB.getConclusion().getIndication());

        XmlSAV xmlSAV = sigBBB.getSAV();
        assertNotNull(xmlSAV);
        assertEquals(Indication.PASSED, xmlSAV.getConclusion().getIndication());

        boolean signCertCheckPresent = false;
        boolean signCertOnlyOneCheckPresent = false;
        boolean kidCheckPresent = false;
        boolean signTimeCheckPresent = false;
        boolean ctyCheckPresent = false;
        for (XmlConstraint xmlConstraint : xmlSAV.getConstraint()) {
            assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
            if (MessageTag.BBB_ICS_ISASCP.getId().equals(xmlConstraint.getName().getKey())) {
                signCertCheckPresent = true;
            } else if (MessageTag.BBB_ICS_ISASCPU.getId().equals(xmlConstraint.getName().getKey())) {
                signCertOnlyOneCheckPresent = true;
            } else if (MessageTag.BBB_ICS_ISAKIDP.getId().equals(xmlConstraint.getName().getKey())) {
                kidCheckPresent = true;
            } else if (MessageTag.BBB_SAV_ISQPSTP.getId().equals(xmlConstraint.getName().getKey())) {
                signTimeCheckPresent = true;
            } else if (MessageTag.BBB_SAV_ISQPCTP.getId().equals(xmlConstraint.getName().getKey())) {
                ctyCheckPresent = true;
            }
        }
        assertTrue(signCertCheckPresent);
        assertTrue(signCertOnlyOneCheckPresent);
        assertTrue(kidCheckPresent);
        assertTrue(signTimeCheckPresent);
        assertTrue(ctyCheckPresent);

        eu.europa.esig.dss.diagnostic.jaxb.XmlCertificate signingCertificate =
                tlsCertificateBindingSignature.getSigningCertificate().getCertificate();
        assertEquals(QWACProfile.QWAC_2, detailedReport.getCertificateQWACProfile(signingCertificate.getId()));

        eu.europa.esig.dss.detailedreport.jaxb.XmlSignature xmlSignature = detailedReport.getXmlSignatureById(tlsCertificateBindingSignature.getId());
        assertEquals(Indication.TOTAL_PASSED, xmlSignature.getConclusion().getIndication());

        XmlValidationSignatureQualification signatureQualification = xmlSignature.getValidationSignatureQualification();
        assertEquals(SignatureQualification.NOT_ADES, signatureQualification.getSignatureQualification());

        XmlQWACProcess signatureQWACProcess = signatureQualification.getQWACProcess();
        assertEquals(signingCertificate.getId(), signatureQWACProcess.getId());
        assertEquals(QWACProfile.QWAC_2, signatureQWACProcess.getQWACType());
        assertEquals(Indication.PASSED, signatureQWACProcess.getConclusion().getIndication());

        // 2-qwac checks
        boolean certPolicyCheckPresent = false;
        boolean certQualConclusiveCheckPresent = false;
        boolean wsaCheckAtIssuanceTimePresent = false;
        boolean wsaCheckAtValidationTimePresent = false;
        boolean certValidityPeriodCheckPresent = false;
        boolean domainNamePresent = false;
        boolean extKeyUsageCheckPresent = false;
        boolean bbbCheckConclusive = false;
        boolean is2QWACProcessPresent = false;
        for (XmlValidationQWACProcess xmlValidationQWACProcess : signatureQWACProcess.getValidationQWACProcess()) {
            if (i18nProvider.getMessage(MessageTag.QWAC_VALIDATION_PROFILE,
                    ValidationProcessUtils.getQWACValidationMessageTag(QWACProfile.QWAC_2)).equals(xmlValidationQWACProcess.getTitle())) {
                assertEquals(Indication.PASSED, xmlValidationQWACProcess.getConclusion().getIndication());
                for (XmlConstraint xmlConstraint : xmlValidationQWACProcess.getConstraint()) {
                    assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                    if (MessageTag.QWAC_CERT_POLICY.getId().equals(xmlConstraint.getName().getKey())) {
                        certPolicyCheckPresent = true;
                    } else if (MessageTag.QWAC_CERT_QUAL_CONCLUSIVE.getId().equals(xmlConstraint.getName().getKey())) {
                        certQualConclusiveCheckPresent = true;
                    } else if (MessageTag.QWAC_IS_WSA_AT_TIME.getId().equals(xmlConstraint.getName().getKey())) {
                        if (i18nProvider.getMessage(MessageTag.QWAC_IS_WSA_AT_TIME, ValidationProcessUtils.getValidationTimeMessageTag(
                                ValidationTime.CERTIFICATE_ISSUANCE_TIME)).equals(xmlConstraint.getName().getValue())) {
                            wsaCheckAtIssuanceTimePresent = true;
                        } else if (i18nProvider.getMessage(MessageTag.QWAC_IS_WSA_AT_TIME, ValidationProcessUtils.getValidationTimeMessageTag(
                                ValidationTime.VALIDATION_TIME)).equals(xmlConstraint.getName().getValue())) {
                            wsaCheckAtValidationTimePresent = true;
                        }
                    } else if (MessageTag.QWAC_VAL_PERIOD.getId().equals(xmlConstraint.getName().getKey())) {
                        certValidityPeriodCheckPresent = true;
                    } else if (MessageTag.QWAC_DOMAIN_NAME.getId().equals(xmlConstraint.getName().getKey())) {
                        domainNamePresent = true;
                    } else if (MessageTag.QWAC2_EXT_KEY_USAGE.getId().equals(xmlConstraint.getName().getKey())) {
                        extKeyUsageCheckPresent = true;
                    } else if (MessageTag.BBB_ACCEPT.getId().equals(xmlConstraint.getName().getKey())) {
                        bbbCheckConclusive = true;
                    }
                }

                is2QWACProcessPresent = true;
            }
        }
        assertTrue(certPolicyCheckPresent);
        assertTrue(certQualConclusiveCheckPresent);
        assertTrue(wsaCheckAtIssuanceTimePresent);
        assertTrue(wsaCheckAtValidationTimePresent);
        assertTrue(certValidityPeriodCheckPresent);
        assertTrue(domainNamePresent);
        assertTrue(extKeyUsageCheckPresent);
        assertTrue(bbbCheckConclusive);
        assertTrue(is2QWACProcessPresent);

        checkReports(reports);
    }

    @Test
    void tlsNoLinkHeaderTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/qwac-validation/2-qwac-valid-diag-data.xml"));
        assertNotNull(diagnosticData);

        diagnosticData.getConnectionInfo().setTLSCertificateBindingUrl(null);

        String certificateId = "C-83D242F9A51C7A62BA1B774268EAAECBAB097479E83D8675C14F02DFB269FE77";

        QWACCertificateProcessExecutor executor = new QWACCertificateProcessExecutor();
        executor.setCertificateId(certificateId);
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        CertificateReports reports = executor.execute();

        SimpleCertificateReport simpleReport = reports.getSimpleReport();
        assertNotNull(simpleReport);

        assertEquals(QWACProfile.NOT_QWAC, simpleReport.getQWACProfile());
        assertEquals(QWACProfile.QWAC_2, simpleReport.getTLSBindingSignatureIssuerCertificateQWACProfile());

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(QWACProfile.NOT_QWAC, detailedReport.getCertificateQWACProfile(certificateId));

        XmlCertificate xmlCertificate = detailedReport.getXmlCertificateById(certificateId);
        assertNotNull(xmlCertificate);

        XmlQWACProcess qwacProcess = xmlCertificate.getQWACProcess();
        assertNotNull(qwacProcess);
        assertEquals(certificateId, qwacProcess.getId());
        assertEquals(QWACProfile.NOT_QWAC, qwacProcess.getQWACType());
        assertEquals(Indication.FAILED, qwacProcess.getConclusion().getIndication());

        boolean isQWACValidCheckFound = false;
        for (XmlConstraint xmlConstraint : qwacProcess.getConstraint()) {
            if (MessageTag.QWAC_VALID.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                assertEquals(MessageTag.QWAC_VALID_ANS.getId(), xmlConstraint.getError().getKey());
                isQWACValidCheckFound = true;
            }
        }
        assertTrue(isQWACValidCheckFound);

        // 1-qwac checks
        boolean is1QWACProcessPresent = false;
        boolean bbbCheckPresent = false;
        boolean qwac1DomainNamePresent = false;
        boolean linkHeaderPresent = false;
        boolean sigFormCheckPresent = false;
        boolean jadesCheckPresent = false;
        boolean jadesCompactCheckPresent = false;
        boolean expTimeCheckPresent = false;
        boolean sigExpCheckPresent = false;
        boolean qwac2CheckPresent = false;
        boolean sigValidCheckPresent = false;
        boolean tlsCertBindingValidCheckPresent = false;

        boolean isTlsSupportedBy2QWACProcessPresent = false;
        for (XmlValidationQWACProcess xmlValidationQWACProcess : qwacProcess.getValidationQWACProcess()) {
            if (i18nProvider.getMessage(MessageTag.QWAC_VALIDATION_PROFILE,
                    ValidationProcessUtils.getQWACValidationMessageTag(QWACProfile.QWAC_1)).equals(xmlValidationQWACProcess.getTitle())) {
                assertEquals(Indication.FAILED, xmlValidationQWACProcess.getConclusion().getIndication());
                is1QWACProcessPresent = true;

            } else if (i18nProvider.getMessage(MessageTag.QWAC_VALIDATION_PROFILE,
                    ValidationProcessUtils.getQWACValidationMessageTag(QWACProfile.TLS_BY_QWAC_2)).equals(xmlValidationQWACProcess.getTitle())) {
                assertEquals(Indication.FAILED, xmlValidationQWACProcess.getConclusion().getIndication());
                for (XmlConstraint xmlConstraint : xmlValidationQWACProcess.getConstraint()) {
                    if (MessageTag.BBB_ACCEPT.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        bbbCheckPresent = true;
                    } else if (MessageTag.QWAC_DOMAIN_NAME.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        qwac1DomainNamePresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_URL.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                        assertEquals(MessageTag.TLS_CERT_BINDING_URL_ANS.getId(), xmlConstraint.getError().getKey());
                        linkHeaderPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG.getId().equals(xmlConstraint.getName().getKey())) {
                        sigFormCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG_FORM.getId().equals(xmlConstraint.getName().getKey())) {
                        jadesCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG_SER.getId().equals(xmlConstraint.getName().getKey())) {
                        jadesCompactCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG_EXP.getId().equals(xmlConstraint.getName().getKey())) {
                        expTimeCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG_EXPIRY_DATE.getId().equals(xmlConstraint.getName().getKey())) {
                        sigExpCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_QWAC2.getId().equals(xmlConstraint.getName().getKey())) {
                        qwac2CheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG_VALID.getId().equals(xmlConstraint.getName().getKey())) {
                        sigValidCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_CERT_IDENTIFIED.getId().equals(xmlConstraint.getName().getKey())) {
                        tlsCertBindingValidCheckPresent = true;
                    }
                }

                isTlsSupportedBy2QWACProcessPresent = true;
            }
        }
        assertTrue(is1QWACProcessPresent);
        assertTrue(bbbCheckPresent);
        assertTrue(qwac1DomainNamePresent);
        assertTrue(linkHeaderPresent);
        assertFalse(sigFormCheckPresent);
        assertFalse(jadesCheckPresent);
        assertFalse(jadesCompactCheckPresent);
        assertFalse(expTimeCheckPresent);
        assertFalse(sigExpCheckPresent);
        assertFalse(qwac2CheckPresent);
        assertFalse(sigValidCheckPresent);
        assertFalse(tlsCertBindingValidCheckPresent);
        assertTrue(isTlsSupportedBy2QWACProcessPresent);

        XmlSignature tlsCertificateBindingSignature = diagnosticData
                .getConnectionInfo().getTLSCertificateBindingSignature().getSignature();

        XmlBasicBuildingBlocks sigBBB = detailedReport.getBasicBuildingBlockById(tlsCertificateBindingSignature.getId());
        assertNotNull(sigBBB);
        assertEquals(Indication.PASSED, sigBBB.getConclusion().getIndication());

        XmlSAV xmlSAV = sigBBB.getSAV();
        assertNotNull(xmlSAV);
        assertEquals(Indication.PASSED, xmlSAV.getConclusion().getIndication());

        boolean signCertCheckPresent = false;
        boolean signCertOnlyOneCheckPresent = false;
        boolean kidCheckPresent = false;
        boolean signTimeCheckPresent = false;
        boolean ctyCheckPresent = false;
        for (XmlConstraint xmlConstraint : xmlSAV.getConstraint()) {
            assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
            if (MessageTag.BBB_ICS_ISASCP.getId().equals(xmlConstraint.getName().getKey())) {
                signCertCheckPresent = true;
            } else if (MessageTag.BBB_ICS_ISASCPU.getId().equals(xmlConstraint.getName().getKey())) {
                signCertOnlyOneCheckPresent = true;
            } else if (MessageTag.BBB_ICS_ISAKIDP.getId().equals(xmlConstraint.getName().getKey())) {
                kidCheckPresent = true;
            } else if (MessageTag.BBB_SAV_ISQPSTP.getId().equals(xmlConstraint.getName().getKey())) {
                signTimeCheckPresent = true;
            } else if (MessageTag.BBB_SAV_ISQPCTP.getId().equals(xmlConstraint.getName().getKey())) {
                ctyCheckPresent = true;
            }
        }
        assertTrue(signCertCheckPresent);
        assertTrue(signCertOnlyOneCheckPresent);
        assertTrue(kidCheckPresent);
        assertTrue(signTimeCheckPresent);
        assertTrue(ctyCheckPresent);

        eu.europa.esig.dss.diagnostic.jaxb.XmlCertificate signingCertificate =
                tlsCertificateBindingSignature.getSigningCertificate().getCertificate();
        assertEquals(QWACProfile.QWAC_2, detailedReport.getCertificateQWACProfile(signingCertificate.getId()));

        eu.europa.esig.dss.detailedreport.jaxb.XmlSignature xmlSignature = detailedReport.getXmlSignatureById(tlsCertificateBindingSignature.getId());
        assertEquals(Indication.TOTAL_PASSED, xmlSignature.getConclusion().getIndication());

        XmlValidationSignatureQualification signatureQualification = xmlSignature.getValidationSignatureQualification();
        assertEquals(SignatureQualification.NOT_ADES, signatureQualification.getSignatureQualification());

        XmlQWACProcess signatureQWACProcess = signatureQualification.getQWACProcess();
        assertEquals(signingCertificate.getId(), signatureQWACProcess.getId());
        assertEquals(QWACProfile.QWAC_2, signatureQWACProcess.getQWACType());
        assertEquals(Indication.PASSED, signatureQWACProcess.getConclusion().getIndication());

        // 2-qwac checks
        boolean certPolicyCheckPresent = false;
        boolean certQualConclusiveCheckPresent = false;
        boolean wsaCheckAtIssuanceTimePresent = false;
        boolean wsaCheckAtValidationTimePresent = false;
        boolean certValidityPeriodCheckPresent = false;
        boolean domainNamePresent = false;
        boolean extKeyUsageCheckPresent = false;
        boolean bbbCheckConclusive = false;
        boolean is2QWACProcessPresent = false;
        for (XmlValidationQWACProcess xmlValidationQWACProcess : signatureQWACProcess.getValidationQWACProcess()) {
            if (i18nProvider.getMessage(MessageTag.QWAC_VALIDATION_PROFILE,
                    ValidationProcessUtils.getQWACValidationMessageTag(QWACProfile.QWAC_2)).equals(xmlValidationQWACProcess.getTitle())) {
                assertEquals(Indication.PASSED, xmlValidationQWACProcess.getConclusion().getIndication());
                for (XmlConstraint xmlConstraint : xmlValidationQWACProcess.getConstraint()) {
                    assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                    if (MessageTag.QWAC_CERT_POLICY.getId().equals(xmlConstraint.getName().getKey())) {
                        certPolicyCheckPresent = true;
                    } else if (MessageTag.QWAC_CERT_QUAL_CONCLUSIVE.getId().equals(xmlConstraint.getName().getKey())) {
                        certQualConclusiveCheckPresent = true;
                    } else if (MessageTag.QWAC_IS_WSA_AT_TIME.getId().equals(xmlConstraint.getName().getKey())) {
                        if (i18nProvider.getMessage(MessageTag.QWAC_IS_WSA_AT_TIME, ValidationProcessUtils.getValidationTimeMessageTag(
                                ValidationTime.CERTIFICATE_ISSUANCE_TIME)).equals(xmlConstraint.getName().getValue())) {
                            wsaCheckAtIssuanceTimePresent = true;
                        } else if (i18nProvider.getMessage(MessageTag.QWAC_IS_WSA_AT_TIME, ValidationProcessUtils.getValidationTimeMessageTag(
                                ValidationTime.VALIDATION_TIME)).equals(xmlConstraint.getName().getValue())) {
                            wsaCheckAtValidationTimePresent = true;
                        }
                    } else if (MessageTag.QWAC_VAL_PERIOD.getId().equals(xmlConstraint.getName().getKey())) {
                        certValidityPeriodCheckPresent = true;
                    } else if (MessageTag.QWAC_DOMAIN_NAME.getId().equals(xmlConstraint.getName().getKey())) {
                        domainNamePresent = true;
                    } else if (MessageTag.QWAC2_EXT_KEY_USAGE.getId().equals(xmlConstraint.getName().getKey())) {
                        extKeyUsageCheckPresent = true;
                    } else if (MessageTag.BBB_ACCEPT.getId().equals(xmlConstraint.getName().getKey())) {
                        bbbCheckConclusive = true;
                    }
                }

                is2QWACProcessPresent = true;
            }
        }
        assertTrue(certPolicyCheckPresent);
        assertTrue(certQualConclusiveCheckPresent);
        assertTrue(wsaCheckAtIssuanceTimePresent);
        assertTrue(wsaCheckAtValidationTimePresent);
        assertTrue(certValidityPeriodCheckPresent);
        assertTrue(domainNamePresent);
        assertTrue(extKeyUsageCheckPresent);
        assertTrue(bbbCheckConclusive);
        assertTrue(is2QWACProcessPresent);

        checkReports(reports);
    }

    @Test
    void tlsNoSigPresentTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/qwac-validation/2-qwac-valid-diag-data.xml"));
        assertNotNull(diagnosticData);

        diagnosticData.getConnectionInfo().setTLSCertificateBindingSignature(null);
        diagnosticData.getSignatures().clear();

        String certificateId = "C-83D242F9A51C7A62BA1B774268EAAECBAB097479E83D8675C14F02DFB269FE77";

        QWACCertificateProcessExecutor executor = new QWACCertificateProcessExecutor();
        executor.setCertificateId(certificateId);
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        CertificateReports reports = executor.execute();

        SimpleCertificateReport simpleReport = reports.getSimpleReport();
        assertNotNull(simpleReport);

        assertEquals(QWACProfile.NOT_QWAC, simpleReport.getQWACProfile());
        assertNull(simpleReport.getTLSBindingSignatureIssuerCertificateQWACProfile());

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(QWACProfile.NOT_QWAC, detailedReport.getCertificateQWACProfile(certificateId));

        XmlCertificate xmlCertificate = detailedReport.getXmlCertificateById(certificateId);
        assertNotNull(xmlCertificate);

        XmlQWACProcess qwacProcess = xmlCertificate.getQWACProcess();
        assertNotNull(qwacProcess);
        assertEquals(certificateId, qwacProcess.getId());
        assertEquals(QWACProfile.NOT_QWAC, qwacProcess.getQWACType());
        assertEquals(Indication.FAILED, qwacProcess.getConclusion().getIndication());

        boolean isQWACValidCheckFound = false;
        for (XmlConstraint xmlConstraint : qwacProcess.getConstraint()) {
            if (MessageTag.QWAC_VALID.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                assertEquals(MessageTag.QWAC_VALID_ANS.getId(), xmlConstraint.getError().getKey());
                isQWACValidCheckFound = true;
            }
        }
        assertTrue(isQWACValidCheckFound);

        // 1-qwac checks
        boolean is1QWACProcessPresent = false;
        boolean bbbCheckPresent = false;
        boolean qwac1DomainNamePresent = false;
        boolean linkHeaderPresent = false;
        boolean sigFormCheckPresent = false;
        boolean jadesCheckPresent = false;
        boolean jadesCompactCheckPresent = false;
        boolean expTimeCheckPresent = false;
        boolean sigExpCheckPresent = false;
        boolean qwac2CheckPresent = false;
        boolean sigValidCheckPresent = false;
        boolean tlsCertBindingValidCheckPresent = false;

        boolean isTlsSupportedBy2QWACProcessPresent = false;
        for (XmlValidationQWACProcess xmlValidationQWACProcess : qwacProcess.getValidationQWACProcess()) {
            if (i18nProvider.getMessage(MessageTag.QWAC_VALIDATION_PROFILE,
                    ValidationProcessUtils.getQWACValidationMessageTag(QWACProfile.QWAC_1)).equals(xmlValidationQWACProcess.getTitle())) {
                assertEquals(Indication.FAILED, xmlValidationQWACProcess.getConclusion().getIndication());
                is1QWACProcessPresent = true;

            } else if (i18nProvider.getMessage(MessageTag.QWAC_VALIDATION_PROFILE,
                    ValidationProcessUtils.getQWACValidationMessageTag(QWACProfile.TLS_BY_QWAC_2)).equals(xmlValidationQWACProcess.getTitle())) {
                assertEquals(Indication.FAILED, xmlValidationQWACProcess.getConclusion().getIndication());
                for (XmlConstraint xmlConstraint : xmlValidationQWACProcess.getConstraint()) {
                    if (MessageTag.BBB_ACCEPT.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        bbbCheckPresent = true;
                    } else if (MessageTag.QWAC_DOMAIN_NAME.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        qwac1DomainNamePresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_URL.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        linkHeaderPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                        assertEquals(MessageTag.TLS_CERT_BINDING_SIG_ANS.getId(), xmlConstraint.getError().getKey());
                        sigFormCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG_FORM.getId().equals(xmlConstraint.getName().getKey())) {
                        jadesCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG_SER.getId().equals(xmlConstraint.getName().getKey())) {
                        jadesCompactCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG_EXP.getId().equals(xmlConstraint.getName().getKey())) {
                        expTimeCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG_EXPIRY_DATE.getId().equals(xmlConstraint.getName().getKey())) {
                        sigExpCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_QWAC2.getId().equals(xmlConstraint.getName().getKey())) {
                        qwac2CheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG_VALID.getId().equals(xmlConstraint.getName().getKey())) {
                        sigValidCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_CERT_IDENTIFIED.getId().equals(xmlConstraint.getName().getKey())) {
                        tlsCertBindingValidCheckPresent = true;
                    }
                }

                isTlsSupportedBy2QWACProcessPresent = true;
            }
        }
        assertTrue(is1QWACProcessPresent);
        assertTrue(bbbCheckPresent);
        assertTrue(qwac1DomainNamePresent);
        assertTrue(linkHeaderPresent);
        assertTrue(sigFormCheckPresent);
        assertFalse(jadesCheckPresent);
        assertFalse(jadesCompactCheckPresent);
        assertFalse(expTimeCheckPresent);
        assertFalse(sigExpCheckPresent);
        assertFalse(qwac2CheckPresent);
        assertFalse(sigValidCheckPresent);
        assertFalse(tlsCertBindingValidCheckPresent);
        assertTrue(isTlsSupportedBy2QWACProcessPresent);

        checkReports(reports);
    }

    @Test
    void tlsXAdESSigTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/qwac-validation/2-qwac-valid-diag-data.xml"));
        assertNotNull(diagnosticData);

        XmlSignature signature = diagnosticData.getSignatures().get(0);
        signature.setSignatureFormat(SignatureLevel.XAdES_BASELINE_B);
        signature.setContentType("TLS-Certificate-Binding-v1"); // different envelope for XAdES

        String certificateId = "C-83D242F9A51C7A62BA1B774268EAAECBAB097479E83D8675C14F02DFB269FE77";

        QWACCertificateProcessExecutor executor = new QWACCertificateProcessExecutor();
        executor.setCertificateId(certificateId);
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        CertificateReports reports = executor.execute();

        SimpleCertificateReport simpleReport = reports.getSimpleReport();
        assertNotNull(simpleReport);

        assertEquals(QWACProfile.NOT_QWAC, simpleReport.getQWACProfile());
        assertEquals(QWACProfile.QWAC_2, simpleReport.getTLSBindingSignatureIssuerCertificateQWACProfile());

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(QWACProfile.NOT_QWAC, detailedReport.getCertificateQWACProfile(certificateId));

        XmlCertificate xmlCertificate = detailedReport.getXmlCertificateById(certificateId);
        assertNotNull(xmlCertificate);

        XmlQWACProcess qwacProcess = xmlCertificate.getQWACProcess();
        assertNotNull(qwacProcess);
        assertEquals(certificateId, qwacProcess.getId());
        assertEquals(QWACProfile.NOT_QWAC, qwacProcess.getQWACType());
        assertEquals(Indication.FAILED, qwacProcess.getConclusion().getIndication());

        boolean isQWACValidCheckFound = false;
        for (XmlConstraint xmlConstraint : qwacProcess.getConstraint()) {
            if (MessageTag.QWAC_VALID.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                assertEquals(MessageTag.QWAC_VALID_ANS.getId(), xmlConstraint.getError().getKey());
                isQWACValidCheckFound = true;
            }
        }
        assertTrue(isQWACValidCheckFound);

        // 1-qwac checks
        boolean is1QWACProcessPresent = false;
        boolean bbbCheckPresent = false;
        boolean qwac1DomainNamePresent = false;
        boolean linkHeaderPresent = false;
        boolean sigFormCheckPresent = false;
        boolean jadesCheckPresent = false;
        boolean jadesCompactCheckPresent = false;
        boolean expTimeCheckPresent = false;
        boolean sigExpCheckPresent = false;
        boolean qwac2CheckPresent = false;
        boolean sigValidCheckPresent = false;
        boolean tlsCertBindingValidCheckPresent = false;

        boolean isTlsSupportedBy2QWACProcessPresent = false;
        for (XmlValidationQWACProcess xmlValidationQWACProcess : qwacProcess.getValidationQWACProcess()) {
            if (i18nProvider.getMessage(MessageTag.QWAC_VALIDATION_PROFILE,
                    ValidationProcessUtils.getQWACValidationMessageTag(QWACProfile.QWAC_1)).equals(xmlValidationQWACProcess.getTitle())) {
                assertEquals(Indication.FAILED, xmlValidationQWACProcess.getConclusion().getIndication());
                is1QWACProcessPresent = true;

            } else if (i18nProvider.getMessage(MessageTag.QWAC_VALIDATION_PROFILE,
                    ValidationProcessUtils.getQWACValidationMessageTag(QWACProfile.TLS_BY_QWAC_2)).equals(xmlValidationQWACProcess.getTitle())) {
                assertEquals(Indication.FAILED, xmlValidationQWACProcess.getConclusion().getIndication());
                for (XmlConstraint xmlConstraint : xmlValidationQWACProcess.getConstraint()) {
                    if (MessageTag.BBB_ACCEPT.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        bbbCheckPresent = true;
                    } else if (MessageTag.QWAC_DOMAIN_NAME.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        qwac1DomainNamePresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_URL.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        linkHeaderPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        sigFormCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG_FORM.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                        assertEquals(MessageTag.TLS_CERT_BINDING_SIG_FORM_ANS.getId(), xmlConstraint.getError().getKey());
                        jadesCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG_SER.getId().equals(xmlConstraint.getName().getKey())) {
                        jadesCompactCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG_EXP.getId().equals(xmlConstraint.getName().getKey())) {
                        expTimeCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG_EXPIRY_DATE.getId().equals(xmlConstraint.getName().getKey())) {
                        sigExpCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_QWAC2.getId().equals(xmlConstraint.getName().getKey())) {
                        qwac2CheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG_VALID.getId().equals(xmlConstraint.getName().getKey())) {
                        sigValidCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_CERT_IDENTIFIED.getId().equals(xmlConstraint.getName().getKey())) {
                        tlsCertBindingValidCheckPresent = true;
                    }
                }

                isTlsSupportedBy2QWACProcessPresent = true;
            }
        }
        assertTrue(is1QWACProcessPresent);
        assertTrue(bbbCheckPresent);
        assertTrue(qwac1DomainNamePresent);
        assertTrue(linkHeaderPresent);
        assertTrue(sigFormCheckPresent);
        assertTrue(jadesCheckPresent);
        assertFalse(jadesCompactCheckPresent);
        assertFalse(expTimeCheckPresent);
        assertFalse(sigExpCheckPresent);
        assertFalse(qwac2CheckPresent);
        assertFalse(sigValidCheckPresent);
        assertFalse(tlsCertBindingValidCheckPresent);
        assertTrue(isTlsSupportedBy2QWACProcessPresent);

        XmlSignature tlsCertificateBindingSignature = diagnosticData
                .getConnectionInfo().getTLSCertificateBindingSignature().getSignature();

        XmlBasicBuildingBlocks sigBBB = detailedReport.getBasicBuildingBlockById(tlsCertificateBindingSignature.getId());
        assertNotNull(sigBBB);
        assertEquals(Indication.PASSED, sigBBB.getConclusion().getIndication());

        XmlSAV xmlSAV = sigBBB.getSAV();
        assertNotNull(xmlSAV);
        assertEquals(Indication.PASSED, xmlSAV.getConclusion().getIndication());

        boolean signCertCheckPresent = false;
        boolean signCertOnlyOneCheckPresent = false;
        boolean kidCheckPresent = false;
        boolean signTimeCheckPresent = false;
        boolean ctyCheckPresent = false;
        for (XmlConstraint xmlConstraint : xmlSAV.getConstraint()) {
            assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
            if (MessageTag.BBB_ICS_ISASCP.getId().equals(xmlConstraint.getName().getKey())) {
                signCertCheckPresent = true;
            } else if (MessageTag.BBB_ICS_ISASCPU.getId().equals(xmlConstraint.getName().getKey())) {
                signCertOnlyOneCheckPresent = true;
            } else if (MessageTag.BBB_ICS_ISAKIDP.getId().equals(xmlConstraint.getName().getKey())) {
                kidCheckPresent = true;
            } else if (MessageTag.BBB_SAV_ISQPSTP.getId().equals(xmlConstraint.getName().getKey())) {
                signTimeCheckPresent = true;
            } else if (MessageTag.BBB_SAV_ISQPCTP.getId().equals(xmlConstraint.getName().getKey())) {
                ctyCheckPresent = true;
            }
        }
        assertTrue(signCertCheckPresent);
        assertTrue(signCertOnlyOneCheckPresent);
        assertFalse(kidCheckPresent); // not JAdES
        assertTrue(signTimeCheckPresent);
        assertTrue(ctyCheckPresent);

        eu.europa.esig.dss.diagnostic.jaxb.XmlCertificate signingCertificate =
                tlsCertificateBindingSignature.getSigningCertificate().getCertificate();
        assertEquals(QWACProfile.QWAC_2, detailedReport.getCertificateQWACProfile(signingCertificate.getId()));

        eu.europa.esig.dss.detailedreport.jaxb.XmlSignature xmlSignature = detailedReport.getXmlSignatureById(tlsCertificateBindingSignature.getId());
        assertEquals(Indication.TOTAL_PASSED, xmlSignature.getConclusion().getIndication());

        XmlValidationSignatureQualification signatureQualification = xmlSignature.getValidationSignatureQualification();
        assertEquals(SignatureQualification.NOT_ADES, signatureQualification.getSignatureQualification());

        XmlQWACProcess signatureQWACProcess = signatureQualification.getQWACProcess();
        assertEquals(signingCertificate.getId(), signatureQWACProcess.getId());
        assertEquals(QWACProfile.QWAC_2, signatureQWACProcess.getQWACType());
        assertEquals(Indication.PASSED, signatureQWACProcess.getConclusion().getIndication());

        // 2-qwac checks
        boolean certPolicyCheckPresent = false;
        boolean certQualConclusiveCheckPresent = false;
        boolean wsaCheckAtIssuanceTimePresent = false;
        boolean wsaCheckAtValidationTimePresent = false;
        boolean certValidityPeriodCheckPresent = false;
        boolean domainNamePresent = false;
        boolean extKeyUsageCheckPresent = false;
        boolean bbbCheckConclusive = false;
        boolean is2QWACProcessPresent = false;
        for (XmlValidationQWACProcess xmlValidationQWACProcess : signatureQWACProcess.getValidationQWACProcess()) {
            if (i18nProvider.getMessage(MessageTag.QWAC_VALIDATION_PROFILE,
                    ValidationProcessUtils.getQWACValidationMessageTag(QWACProfile.QWAC_2)).equals(xmlValidationQWACProcess.getTitle())) {
                assertEquals(Indication.PASSED, xmlValidationQWACProcess.getConclusion().getIndication());
                for (XmlConstraint xmlConstraint : xmlValidationQWACProcess.getConstraint()) {
                    assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                    if (MessageTag.QWAC_CERT_POLICY.getId().equals(xmlConstraint.getName().getKey())) {
                        certPolicyCheckPresent = true;
                    } else if (MessageTag.QWAC_CERT_QUAL_CONCLUSIVE.getId().equals(xmlConstraint.getName().getKey())) {
                        certQualConclusiveCheckPresent = true;
                    } else if (MessageTag.QWAC_IS_WSA_AT_TIME.getId().equals(xmlConstraint.getName().getKey())) {
                        if (i18nProvider.getMessage(MessageTag.QWAC_IS_WSA_AT_TIME, ValidationProcessUtils.getValidationTimeMessageTag(
                                ValidationTime.CERTIFICATE_ISSUANCE_TIME)).equals(xmlConstraint.getName().getValue())) {
                            wsaCheckAtIssuanceTimePresent = true;
                        } else if (i18nProvider.getMessage(MessageTag.QWAC_IS_WSA_AT_TIME, ValidationProcessUtils.getValidationTimeMessageTag(
                                ValidationTime.VALIDATION_TIME)).equals(xmlConstraint.getName().getValue())) {
                            wsaCheckAtValidationTimePresent = true;
                        }
                    } else if (MessageTag.QWAC_VAL_PERIOD.getId().equals(xmlConstraint.getName().getKey())) {
                        certValidityPeriodCheckPresent = true;
                    } else if (MessageTag.QWAC_DOMAIN_NAME.getId().equals(xmlConstraint.getName().getKey())) {
                        domainNamePresent = true;
                    } else if (MessageTag.QWAC2_EXT_KEY_USAGE.getId().equals(xmlConstraint.getName().getKey())) {
                        extKeyUsageCheckPresent = true;
                    } else if (MessageTag.BBB_ACCEPT.getId().equals(xmlConstraint.getName().getKey())) {
                        bbbCheckConclusive = true;
                    }
                }

                is2QWACProcessPresent = true;
            }
        }
        assertTrue(certPolicyCheckPresent);
        assertTrue(certQualConclusiveCheckPresent);
        assertTrue(wsaCheckAtIssuanceTimePresent);
        assertTrue(wsaCheckAtValidationTimePresent);
        assertTrue(certValidityPeriodCheckPresent);
        assertTrue(domainNamePresent);
        assertTrue(extKeyUsageCheckPresent);
        assertTrue(bbbCheckConclusive);
        assertTrue(is2QWACProcessPresent);

        checkReports(reports);
    }

    @Test
    void tlsJAdESSerializedTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/qwac-validation/2-qwac-valid-diag-data.xml"));
        assertNotNull(diagnosticData);

        XmlSignature signature = diagnosticData.getSignatures().get(0);
        signature.setJWSSerializationType(JWSSerializationType.FLATTENED_JSON_SERIALIZATION);

        String certificateId = "C-83D242F9A51C7A62BA1B774268EAAECBAB097479E83D8675C14F02DFB269FE77";

        QWACCertificateProcessExecutor executor = new QWACCertificateProcessExecutor();
        executor.setCertificateId(certificateId);
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        CertificateReports reports = executor.execute();

        SimpleCertificateReport simpleReport = reports.getSimpleReport();
        assertNotNull(simpleReport);

        assertEquals(QWACProfile.NOT_QWAC, simpleReport.getQWACProfile());
        assertEquals(QWACProfile.QWAC_2, simpleReport.getTLSBindingSignatureIssuerCertificateQWACProfile());

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(QWACProfile.NOT_QWAC, detailedReport.getCertificateQWACProfile(certificateId));

        XmlCertificate xmlCertificate = detailedReport.getXmlCertificateById(certificateId);
        assertNotNull(xmlCertificate);

        XmlQWACProcess qwacProcess = xmlCertificate.getQWACProcess();
        assertNotNull(qwacProcess);
        assertEquals(certificateId, qwacProcess.getId());
        assertEquals(QWACProfile.NOT_QWAC, qwacProcess.getQWACType());
        assertEquals(Indication.FAILED, qwacProcess.getConclusion().getIndication());

        boolean isQWACValidCheckFound = false;
        for (XmlConstraint xmlConstraint : qwacProcess.getConstraint()) {
            if (MessageTag.QWAC_VALID.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                assertEquals(MessageTag.QWAC_VALID_ANS.getId(), xmlConstraint.getError().getKey());
                isQWACValidCheckFound = true;
            }
        }
        assertTrue(isQWACValidCheckFound);

        // 1-qwac checks
        boolean is1QWACProcessPresent = false;
        boolean bbbCheckPresent = false;
        boolean qwac1DomainNamePresent = false;
        boolean linkHeaderPresent = false;
        boolean sigFormCheckPresent = false;
        boolean jadesCheckPresent = false;
        boolean jadesCompactCheckPresent = false;
        boolean expTimeCheckPresent = false;
        boolean sigExpCheckPresent = false;
        boolean qwac2CheckPresent = false;
        boolean sigValidCheckPresent = false;
        boolean tlsCertBindingValidCheckPresent = false;

        boolean isTlsSupportedBy2QWACProcessPresent = false;
        for (XmlValidationQWACProcess xmlValidationQWACProcess : qwacProcess.getValidationQWACProcess()) {
            if (i18nProvider.getMessage(MessageTag.QWAC_VALIDATION_PROFILE,
                    ValidationProcessUtils.getQWACValidationMessageTag(QWACProfile.QWAC_1)).equals(xmlValidationQWACProcess.getTitle())) {
                assertEquals(Indication.FAILED, xmlValidationQWACProcess.getConclusion().getIndication());
                is1QWACProcessPresent = true;

            } else if (i18nProvider.getMessage(MessageTag.QWAC_VALIDATION_PROFILE,
                    ValidationProcessUtils.getQWACValidationMessageTag(QWACProfile.TLS_BY_QWAC_2)).equals(xmlValidationQWACProcess.getTitle())) {
                assertEquals(Indication.FAILED, xmlValidationQWACProcess.getConclusion().getIndication());
                for (XmlConstraint xmlConstraint : xmlValidationQWACProcess.getConstraint()) {
                    if (MessageTag.BBB_ACCEPT.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        bbbCheckPresent = true;
                    } else if (MessageTag.QWAC_DOMAIN_NAME.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        qwac1DomainNamePresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_URL.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        linkHeaderPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        sigFormCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG_FORM.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        jadesCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG_SER.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                        assertEquals(MessageTag.TLS_CERT_BINDING_SIG_SER_ANS.getId(), xmlConstraint.getError().getKey());
                        jadesCompactCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG_EXP.getId().equals(xmlConstraint.getName().getKey())) {
                        expTimeCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG_EXPIRY_DATE.getId().equals(xmlConstraint.getName().getKey())) {
                        sigExpCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_QWAC2.getId().equals(xmlConstraint.getName().getKey())) {
                        qwac2CheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG_VALID.getId().equals(xmlConstraint.getName().getKey())) {
                        sigValidCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_CERT_IDENTIFIED.getId().equals(xmlConstraint.getName().getKey())) {
                        tlsCertBindingValidCheckPresent = true;
                    }
                }

                isTlsSupportedBy2QWACProcessPresent = true;
            }
        }
        assertTrue(is1QWACProcessPresent);
        assertTrue(bbbCheckPresent);
        assertTrue(qwac1DomainNamePresent);
        assertTrue(linkHeaderPresent);
        assertTrue(sigFormCheckPresent);
        assertTrue(jadesCheckPresent);
        assertTrue(jadesCompactCheckPresent);
        assertFalse(expTimeCheckPresent);
        assertFalse(sigExpCheckPresent);
        assertFalse(qwac2CheckPresent);
        assertFalse(sigValidCheckPresent);
        assertFalse(tlsCertBindingValidCheckPresent);
        assertTrue(isTlsSupportedBy2QWACProcessPresent);

        XmlSignature tlsCertificateBindingSignature = diagnosticData
                .getConnectionInfo().getTLSCertificateBindingSignature().getSignature();

        XmlBasicBuildingBlocks sigBBB = detailedReport.getBasicBuildingBlockById(tlsCertificateBindingSignature.getId());
        assertNotNull(sigBBB);
        assertEquals(Indication.PASSED, sigBBB.getConclusion().getIndication());

        XmlSAV xmlSAV = sigBBB.getSAV();
        assertNotNull(xmlSAV);
        assertEquals(Indication.PASSED, xmlSAV.getConclusion().getIndication());

        boolean signCertCheckPresent = false;
        boolean signCertOnlyOneCheckPresent = false;
        boolean kidCheckPresent = false;
        boolean signTimeCheckPresent = false;
        boolean ctyCheckPresent = false;
        for (XmlConstraint xmlConstraint : xmlSAV.getConstraint()) {
            assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
            if (MessageTag.BBB_ICS_ISASCP.getId().equals(xmlConstraint.getName().getKey())) {
                signCertCheckPresent = true;
            } else if (MessageTag.BBB_ICS_ISASCPU.getId().equals(xmlConstraint.getName().getKey())) {
                signCertOnlyOneCheckPresent = true;
            } else if (MessageTag.BBB_ICS_ISAKIDP.getId().equals(xmlConstraint.getName().getKey())) {
                kidCheckPresent = true;
            } else if (MessageTag.BBB_SAV_ISQPSTP.getId().equals(xmlConstraint.getName().getKey())) {
                signTimeCheckPresent = true;
            } else if (MessageTag.BBB_SAV_ISQPCTP.getId().equals(xmlConstraint.getName().getKey())) {
                ctyCheckPresent = true;
            }
        }
        assertTrue(signCertCheckPresent);
        assertTrue(signCertOnlyOneCheckPresent);
        assertTrue(kidCheckPresent);
        assertTrue(signTimeCheckPresent);
        assertTrue(ctyCheckPresent);

        eu.europa.esig.dss.diagnostic.jaxb.XmlCertificate signingCertificate =
                tlsCertificateBindingSignature.getSigningCertificate().getCertificate();
        assertEquals(QWACProfile.QWAC_2, detailedReport.getCertificateQWACProfile(signingCertificate.getId()));

        eu.europa.esig.dss.detailedreport.jaxb.XmlSignature xmlSignature = detailedReport.getXmlSignatureById(tlsCertificateBindingSignature.getId());
        assertEquals(Indication.TOTAL_PASSED, xmlSignature.getConclusion().getIndication());

        XmlValidationSignatureQualification signatureQualification = xmlSignature.getValidationSignatureQualification();
        assertEquals(SignatureQualification.NOT_ADES, signatureQualification.getSignatureQualification());

        XmlQWACProcess signatureQWACProcess = signatureQualification.getQWACProcess();
        assertEquals(signingCertificate.getId(), signatureQWACProcess.getId());
        assertEquals(QWACProfile.QWAC_2, signatureQWACProcess.getQWACType());
        assertEquals(Indication.PASSED, signatureQWACProcess.getConclusion().getIndication());

        // 2-qwac checks
        boolean certPolicyCheckPresent = false;
        boolean certQualConclusiveCheckPresent = false;
        boolean wsaCheckAtIssuanceTimePresent = false;
        boolean wsaCheckAtValidationTimePresent = false;
        boolean certValidityPeriodCheckPresent = false;
        boolean domainNamePresent = false;
        boolean extKeyUsageCheckPresent = false;
        boolean bbbCheckConclusive = false;
        boolean is2QWACProcessPresent = false;
        for (XmlValidationQWACProcess xmlValidationQWACProcess : signatureQWACProcess.getValidationQWACProcess()) {
            if (i18nProvider.getMessage(MessageTag.QWAC_VALIDATION_PROFILE,
                    ValidationProcessUtils.getQWACValidationMessageTag(QWACProfile.QWAC_2)).equals(xmlValidationQWACProcess.getTitle())) {
                assertEquals(Indication.PASSED, xmlValidationQWACProcess.getConclusion().getIndication());
                for (XmlConstraint xmlConstraint : xmlValidationQWACProcess.getConstraint()) {
                    assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                    if (MessageTag.QWAC_CERT_POLICY.getId().equals(xmlConstraint.getName().getKey())) {
                        certPolicyCheckPresent = true;
                    } else if (MessageTag.QWAC_CERT_QUAL_CONCLUSIVE.getId().equals(xmlConstraint.getName().getKey())) {
                        certQualConclusiveCheckPresent = true;
                    } else if (MessageTag.QWAC_IS_WSA_AT_TIME.getId().equals(xmlConstraint.getName().getKey())) {
                        if (i18nProvider.getMessage(MessageTag.QWAC_IS_WSA_AT_TIME, ValidationProcessUtils.getValidationTimeMessageTag(
                                ValidationTime.CERTIFICATE_ISSUANCE_TIME)).equals(xmlConstraint.getName().getValue())) {
                            wsaCheckAtIssuanceTimePresent = true;
                        } else if (i18nProvider.getMessage(MessageTag.QWAC_IS_WSA_AT_TIME, ValidationProcessUtils.getValidationTimeMessageTag(
                                ValidationTime.VALIDATION_TIME)).equals(xmlConstraint.getName().getValue())) {
                            wsaCheckAtValidationTimePresent = true;
                        }
                    } else if (MessageTag.QWAC_VAL_PERIOD.getId().equals(xmlConstraint.getName().getKey())) {
                        certValidityPeriodCheckPresent = true;
                    } else if (MessageTag.QWAC_DOMAIN_NAME.getId().equals(xmlConstraint.getName().getKey())) {
                        domainNamePresent = true;
                    } else if (MessageTag.QWAC2_EXT_KEY_USAGE.getId().equals(xmlConstraint.getName().getKey())) {
                        extKeyUsageCheckPresent = true;
                    } else if (MessageTag.BBB_ACCEPT.getId().equals(xmlConstraint.getName().getKey())) {
                        bbbCheckConclusive = true;
                    }
                }

                is2QWACProcessPresent = true;
            }
        }
        assertTrue(certPolicyCheckPresent);
        assertTrue(certQualConclusiveCheckPresent);
        assertTrue(wsaCheckAtIssuanceTimePresent);
        assertTrue(wsaCheckAtValidationTimePresent);
        assertTrue(certValidityPeriodCheckPresent);
        assertTrue(domainNamePresent);
        assertTrue(extKeyUsageCheckPresent);
        assertTrue(bbbCheckConclusive);
        assertTrue(is2QWACProcessPresent);

        checkReports(reports);
    }

    @Test
    void tlsExpDateNotPresentTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/qwac-validation/2-qwac-valid-diag-data.xml"));
        assertNotNull(diagnosticData);

        XmlSignature signature = diagnosticData.getSignatures().get(0);
        signature.setExpirationTime(null);

        String certificateId = "C-83D242F9A51C7A62BA1B774268EAAECBAB097479E83D8675C14F02DFB269FE77";

        QWACCertificateProcessExecutor executor = new QWACCertificateProcessExecutor();
        executor.setCertificateId(certificateId);
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        CertificateReports reports = executor.execute();

        SimpleCertificateReport simpleReport = reports.getSimpleReport();
        assertNotNull(simpleReport);

        assertEquals(QWACProfile.NOT_QWAC, simpleReport.getQWACProfile());
        assertEquals(QWACProfile.QWAC_2, simpleReport.getTLSBindingSignatureIssuerCertificateQWACProfile());

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(QWACProfile.NOT_QWAC, detailedReport.getCertificateQWACProfile(certificateId));

        XmlCertificate xmlCertificate = detailedReport.getXmlCertificateById(certificateId);
        assertNotNull(xmlCertificate);

        XmlQWACProcess qwacProcess = xmlCertificate.getQWACProcess();
        assertNotNull(qwacProcess);
        assertEquals(certificateId, qwacProcess.getId());
        assertEquals(QWACProfile.NOT_QWAC, qwacProcess.getQWACType());
        assertEquals(Indication.FAILED, qwacProcess.getConclusion().getIndication());

        boolean isQWACValidCheckFound = false;
        for (XmlConstraint xmlConstraint : qwacProcess.getConstraint()) {
            if (MessageTag.QWAC_VALID.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                assertEquals(MessageTag.QWAC_VALID_ANS.getId(), xmlConstraint.getError().getKey());
                isQWACValidCheckFound = true;
            }
        }
        assertTrue(isQWACValidCheckFound);

        // 1-qwac checks
        boolean is1QWACProcessPresent = false;
        boolean bbbCheckPresent = false;
        boolean qwac1DomainNamePresent = false;
        boolean linkHeaderPresent = false;
        boolean sigFormCheckPresent = false;
        boolean jadesCheckPresent = false;
        boolean jadesCompactCheckPresent = false;
        boolean expTimeCheckPresent = false;
        boolean sigExpCheckPresent = false;
        boolean qwac2CheckPresent = false;
        boolean sigValidCheckPresent = false;
        boolean tlsCertBindingValidCheckPresent = false;

        boolean isTlsSupportedBy2QWACProcessPresent = false;
        for (XmlValidationQWACProcess xmlValidationQWACProcess : qwacProcess.getValidationQWACProcess()) {
            if (i18nProvider.getMessage(MessageTag.QWAC_VALIDATION_PROFILE,
                    ValidationProcessUtils.getQWACValidationMessageTag(QWACProfile.QWAC_1)).equals(xmlValidationQWACProcess.getTitle())) {
                assertEquals(Indication.FAILED, xmlValidationQWACProcess.getConclusion().getIndication());
                is1QWACProcessPresent = true;

            } else if (i18nProvider.getMessage(MessageTag.QWAC_VALIDATION_PROFILE,
                    ValidationProcessUtils.getQWACValidationMessageTag(QWACProfile.TLS_BY_QWAC_2)).equals(xmlValidationQWACProcess.getTitle())) {
                assertEquals(Indication.FAILED, xmlValidationQWACProcess.getConclusion().getIndication());
                for (XmlConstraint xmlConstraint : xmlValidationQWACProcess.getConstraint()) {
                    if (MessageTag.BBB_ACCEPT.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        bbbCheckPresent = true;
                    } else if (MessageTag.QWAC_DOMAIN_NAME.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        qwac1DomainNamePresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_URL.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        linkHeaderPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        sigFormCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG_FORM.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        jadesCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG_SER.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        jadesCompactCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG_EXP.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                        assertEquals(MessageTag.TLS_CERT_BINDING_SIG_EXP_ANS.getId(), xmlConstraint.getError().getKey());
                        expTimeCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG_EXPIRY_DATE.getId().equals(xmlConstraint.getName().getKey())) {
                        sigExpCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_QWAC2.getId().equals(xmlConstraint.getName().getKey())) {
                        qwac2CheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG_VALID.getId().equals(xmlConstraint.getName().getKey())) {
                        sigValidCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_CERT_IDENTIFIED.getId().equals(xmlConstraint.getName().getKey())) {
                        tlsCertBindingValidCheckPresent = true;
                    }
                }

                isTlsSupportedBy2QWACProcessPresent = true;
            }
        }
        assertTrue(is1QWACProcessPresent);
        assertTrue(bbbCheckPresent);
        assertTrue(qwac1DomainNamePresent);
        assertTrue(linkHeaderPresent);
        assertTrue(sigFormCheckPresent);
        assertTrue(jadesCheckPresent);
        assertTrue(jadesCompactCheckPresent);
        assertTrue(expTimeCheckPresent);
        assertFalse(sigExpCheckPresent);
        assertFalse(qwac2CheckPresent);
        assertFalse(sigValidCheckPresent);
        assertFalse(tlsCertBindingValidCheckPresent);
        assertTrue(isTlsSupportedBy2QWACProcessPresent);

        XmlSignature tlsCertificateBindingSignature = diagnosticData
                .getConnectionInfo().getTLSCertificateBindingSignature().getSignature();

        XmlBasicBuildingBlocks sigBBB = detailedReport.getBasicBuildingBlockById(tlsCertificateBindingSignature.getId());
        assertNotNull(sigBBB);
        assertEquals(Indication.PASSED, sigBBB.getConclusion().getIndication());

        XmlSAV xmlSAV = sigBBB.getSAV();
        assertNotNull(xmlSAV);
        assertEquals(Indication.PASSED, xmlSAV.getConclusion().getIndication());

        boolean signCertCheckPresent = false;
        boolean signCertOnlyOneCheckPresent = false;
        boolean kidCheckPresent = false;
        boolean signTimeCheckPresent = false;
        boolean ctyCheckPresent = false;
        for (XmlConstraint xmlConstraint : xmlSAV.getConstraint()) {
            assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
            if (MessageTag.BBB_ICS_ISASCP.getId().equals(xmlConstraint.getName().getKey())) {
                signCertCheckPresent = true;
            } else if (MessageTag.BBB_ICS_ISASCPU.getId().equals(xmlConstraint.getName().getKey())) {
                signCertOnlyOneCheckPresent = true;
            } else if (MessageTag.BBB_ICS_ISAKIDP.getId().equals(xmlConstraint.getName().getKey())) {
                kidCheckPresent = true;
            } else if (MessageTag.BBB_SAV_ISQPSTP.getId().equals(xmlConstraint.getName().getKey())) {
                signTimeCheckPresent = true;
            } else if (MessageTag.BBB_SAV_ISQPCTP.getId().equals(xmlConstraint.getName().getKey())) {
                ctyCheckPresent = true;
            }
        }
        assertTrue(signCertCheckPresent);
        assertTrue(signCertOnlyOneCheckPresent);
        assertTrue(kidCheckPresent);
        assertTrue(signTimeCheckPresent);
        assertTrue(ctyCheckPresent);

        eu.europa.esig.dss.diagnostic.jaxb.XmlCertificate signingCertificate =
                tlsCertificateBindingSignature.getSigningCertificate().getCertificate();
        assertEquals(QWACProfile.QWAC_2, detailedReport.getCertificateQWACProfile(signingCertificate.getId()));

        eu.europa.esig.dss.detailedreport.jaxb.XmlSignature xmlSignature = detailedReport.getXmlSignatureById(tlsCertificateBindingSignature.getId());
        assertEquals(Indication.TOTAL_PASSED, xmlSignature.getConclusion().getIndication());

        XmlValidationSignatureQualification signatureQualification = xmlSignature.getValidationSignatureQualification();
        assertEquals(SignatureQualification.NOT_ADES, signatureQualification.getSignatureQualification());

        XmlQWACProcess signatureQWACProcess = signatureQualification.getQWACProcess();
        assertEquals(signingCertificate.getId(), signatureQWACProcess.getId());
        assertEquals(QWACProfile.QWAC_2, signatureQWACProcess.getQWACType());
        assertEquals(Indication.PASSED, signatureQWACProcess.getConclusion().getIndication());

        // 2-qwac checks
        boolean certPolicyCheckPresent = false;
        boolean certQualConclusiveCheckPresent = false;
        boolean wsaCheckAtIssuanceTimePresent = false;
        boolean wsaCheckAtValidationTimePresent = false;
        boolean certValidityPeriodCheckPresent = false;
        boolean domainNamePresent = false;
        boolean extKeyUsageCheckPresent = false;
        boolean bbbCheckConclusive = false;
        boolean is2QWACProcessPresent = false;
        for (XmlValidationQWACProcess xmlValidationQWACProcess : signatureQWACProcess.getValidationQWACProcess()) {
            if (i18nProvider.getMessage(MessageTag.QWAC_VALIDATION_PROFILE,
                    ValidationProcessUtils.getQWACValidationMessageTag(QWACProfile.QWAC_2)).equals(xmlValidationQWACProcess.getTitle())) {
                assertEquals(Indication.PASSED, xmlValidationQWACProcess.getConclusion().getIndication());
                for (XmlConstraint xmlConstraint : xmlValidationQWACProcess.getConstraint()) {
                    assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                    if (MessageTag.QWAC_CERT_POLICY.getId().equals(xmlConstraint.getName().getKey())) {
                        certPolicyCheckPresent = true;
                    } else if (MessageTag.QWAC_CERT_QUAL_CONCLUSIVE.getId().equals(xmlConstraint.getName().getKey())) {
                        certQualConclusiveCheckPresent = true;
                    } else if (MessageTag.QWAC_IS_WSA_AT_TIME.getId().equals(xmlConstraint.getName().getKey())) {
                        if (i18nProvider.getMessage(MessageTag.QWAC_IS_WSA_AT_TIME, ValidationProcessUtils.getValidationTimeMessageTag(
                                ValidationTime.CERTIFICATE_ISSUANCE_TIME)).equals(xmlConstraint.getName().getValue())) {
                            wsaCheckAtIssuanceTimePresent = true;
                        } else if (i18nProvider.getMessage(MessageTag.QWAC_IS_WSA_AT_TIME, ValidationProcessUtils.getValidationTimeMessageTag(
                                ValidationTime.VALIDATION_TIME)).equals(xmlConstraint.getName().getValue())) {
                            wsaCheckAtValidationTimePresent = true;
                        }
                    } else if (MessageTag.QWAC_VAL_PERIOD.getId().equals(xmlConstraint.getName().getKey())) {
                        certValidityPeriodCheckPresent = true;
                    } else if (MessageTag.QWAC_DOMAIN_NAME.getId().equals(xmlConstraint.getName().getKey())) {
                        domainNamePresent = true;
                    } else if (MessageTag.QWAC2_EXT_KEY_USAGE.getId().equals(xmlConstraint.getName().getKey())) {
                        extKeyUsageCheckPresent = true;
                    } else if (MessageTag.BBB_ACCEPT.getId().equals(xmlConstraint.getName().getKey())) {
                        bbbCheckConclusive = true;
                    }
                }

                is2QWACProcessPresent = true;
            }
        }
        assertTrue(certPolicyCheckPresent);
        assertTrue(certQualConclusiveCheckPresent);
        assertTrue(wsaCheckAtIssuanceTimePresent);
        assertTrue(wsaCheckAtValidationTimePresent);
        assertTrue(certValidityPeriodCheckPresent);
        assertTrue(domainNamePresent);
        assertTrue(extKeyUsageCheckPresent);
        assertTrue(bbbCheckConclusive);
        assertTrue(is2QWACProcessPresent);

        checkReports(reports);
    }

    @Test
    void tlsSigExpiredTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/qwac-validation/2-qwac-valid-diag-data.xml"));
        assertNotNull(diagnosticData);

        XmlSignature signature = diagnosticData.getSignatures().get(0);
        Calendar calendar = Calendar.getInstance();
        calendar.set(2025, Calendar.OCTOBER, 1);
        signature.setExpirationTime(calendar.getTime());

        String certificateId = "C-83D242F9A51C7A62BA1B774268EAAECBAB097479E83D8675C14F02DFB269FE77";

        QWACCertificateProcessExecutor executor = new QWACCertificateProcessExecutor();
        executor.setCertificateId(certificateId);
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        CertificateReports reports = executor.execute();

        SimpleCertificateReport simpleReport = reports.getSimpleReport();
        assertNotNull(simpleReport);

        assertEquals(QWACProfile.NOT_QWAC, simpleReport.getQWACProfile());
        assertEquals(QWACProfile.QWAC_2, simpleReport.getTLSBindingSignatureIssuerCertificateQWACProfile());

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(QWACProfile.NOT_QWAC, detailedReport.getCertificateQWACProfile(certificateId));

        XmlCertificate xmlCertificate = detailedReport.getXmlCertificateById(certificateId);
        assertNotNull(xmlCertificate);

        XmlQWACProcess qwacProcess = xmlCertificate.getQWACProcess();
        assertNotNull(qwacProcess);
        assertEquals(certificateId, qwacProcess.getId());
        assertEquals(QWACProfile.NOT_QWAC, qwacProcess.getQWACType());
        assertEquals(Indication.FAILED, qwacProcess.getConclusion().getIndication());

        boolean isQWACValidCheckFound = false;
        for (XmlConstraint xmlConstraint : qwacProcess.getConstraint()) {
            if (MessageTag.QWAC_VALID.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                assertEquals(MessageTag.QWAC_VALID_ANS.getId(), xmlConstraint.getError().getKey());
                isQWACValidCheckFound = true;
            }
        }
        assertTrue(isQWACValidCheckFound);

        // 1-qwac checks
        boolean is1QWACProcessPresent = false;
        boolean bbbCheckPresent = false;
        boolean qwac1DomainNamePresent = false;
        boolean linkHeaderPresent = false;
        boolean sigFormCheckPresent = false;
        boolean jadesCheckPresent = false;
        boolean jadesCompactCheckPresent = false;
        boolean expTimeCheckPresent = false;
        boolean sigExpCheckPresent = false;
        boolean qwac2CheckPresent = false;
        boolean sigValidCheckPresent = false;
        boolean tlsCertBindingValidCheckPresent = false;

        boolean isTlsSupportedBy2QWACProcessPresent = false;
        for (XmlValidationQWACProcess xmlValidationQWACProcess : qwacProcess.getValidationQWACProcess()) {
            if (i18nProvider.getMessage(MessageTag.QWAC_VALIDATION_PROFILE,
                    ValidationProcessUtils.getQWACValidationMessageTag(QWACProfile.QWAC_1)).equals(xmlValidationQWACProcess.getTitle())) {
                assertEquals(Indication.FAILED, xmlValidationQWACProcess.getConclusion().getIndication());
                is1QWACProcessPresent = true;

            } else if (i18nProvider.getMessage(MessageTag.QWAC_VALIDATION_PROFILE,
                    ValidationProcessUtils.getQWACValidationMessageTag(QWACProfile.TLS_BY_QWAC_2)).equals(xmlValidationQWACProcess.getTitle())) {
                assertEquals(Indication.FAILED, xmlValidationQWACProcess.getConclusion().getIndication());
                for (XmlConstraint xmlConstraint : xmlValidationQWACProcess.getConstraint()) {
                    if (MessageTag.BBB_ACCEPT.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        bbbCheckPresent = true;
                    } else if (MessageTag.QWAC_DOMAIN_NAME.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        qwac1DomainNamePresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_URL.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        linkHeaderPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        sigFormCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG_FORM.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        jadesCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG_SER.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        jadesCompactCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG_EXP.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        expTimeCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG_EXPIRY_DATE.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                        assertEquals(MessageTag.TLS_CERT_BINDING_SIG_EXPIRY_DATE_ANS.getId(), xmlConstraint.getError().getKey());
                        sigExpCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_QWAC2.getId().equals(xmlConstraint.getName().getKey())) {
                        qwac2CheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG_VALID.getId().equals(xmlConstraint.getName().getKey())) {
                        sigValidCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_CERT_IDENTIFIED.getId().equals(xmlConstraint.getName().getKey())) {
                        tlsCertBindingValidCheckPresent = true;
                    }
                }

                isTlsSupportedBy2QWACProcessPresent = true;
            }
        }
        assertTrue(is1QWACProcessPresent);
        assertTrue(bbbCheckPresent);
        assertTrue(qwac1DomainNamePresent);
        assertTrue(linkHeaderPresent);
        assertTrue(sigFormCheckPresent);
        assertTrue(jadesCheckPresent);
        assertTrue(jadesCompactCheckPresent);
        assertTrue(expTimeCheckPresent);
        assertTrue(sigExpCheckPresent);
        assertFalse(qwac2CheckPresent);
        assertFalse(sigValidCheckPresent);
        assertFalse(tlsCertBindingValidCheckPresent);
        assertTrue(isTlsSupportedBy2QWACProcessPresent);

        XmlSignature tlsCertificateBindingSignature = diagnosticData
                .getConnectionInfo().getTLSCertificateBindingSignature().getSignature();

        XmlBasicBuildingBlocks sigBBB = detailedReport.getBasicBuildingBlockById(tlsCertificateBindingSignature.getId());
        assertNotNull(sigBBB);
        assertEquals(Indication.PASSED, sigBBB.getConclusion().getIndication());

        XmlSAV xmlSAV = sigBBB.getSAV();
        assertNotNull(xmlSAV);
        assertEquals(Indication.PASSED, xmlSAV.getConclusion().getIndication());

        boolean signCertCheckPresent = false;
        boolean signCertOnlyOneCheckPresent = false;
        boolean kidCheckPresent = false;
        boolean signTimeCheckPresent = false;
        boolean ctyCheckPresent = false;
        for (XmlConstraint xmlConstraint : xmlSAV.getConstraint()) {
            assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
            if (MessageTag.BBB_ICS_ISASCP.getId().equals(xmlConstraint.getName().getKey())) {
                signCertCheckPresent = true;
            } else if (MessageTag.BBB_ICS_ISASCPU.getId().equals(xmlConstraint.getName().getKey())) {
                signCertOnlyOneCheckPresent = true;
            } else if (MessageTag.BBB_ICS_ISAKIDP.getId().equals(xmlConstraint.getName().getKey())) {
                kidCheckPresent = true;
            } else if (MessageTag.BBB_SAV_ISQPSTP.getId().equals(xmlConstraint.getName().getKey())) {
                signTimeCheckPresent = true;
            } else if (MessageTag.BBB_SAV_ISQPCTP.getId().equals(xmlConstraint.getName().getKey())) {
                ctyCheckPresent = true;
            }
        }
        assertTrue(signCertCheckPresent);
        assertTrue(signCertOnlyOneCheckPresent);
        assertTrue(kidCheckPresent);
        assertTrue(signTimeCheckPresent);
        assertTrue(ctyCheckPresent);

        eu.europa.esig.dss.diagnostic.jaxb.XmlCertificate signingCertificate =
                tlsCertificateBindingSignature.getSigningCertificate().getCertificate();
        assertEquals(QWACProfile.QWAC_2, detailedReport.getCertificateQWACProfile(signingCertificate.getId()));

        eu.europa.esig.dss.detailedreport.jaxb.XmlSignature xmlSignature = detailedReport.getXmlSignatureById(tlsCertificateBindingSignature.getId());
        assertEquals(Indication.TOTAL_PASSED, xmlSignature.getConclusion().getIndication());

        XmlValidationSignatureQualification signatureQualification = xmlSignature.getValidationSignatureQualification();
        assertEquals(SignatureQualification.NOT_ADES, signatureQualification.getSignatureQualification());

        XmlQWACProcess signatureQWACProcess = signatureQualification.getQWACProcess();
        assertEquals(signingCertificate.getId(), signatureQWACProcess.getId());
        assertEquals(QWACProfile.QWAC_2, signatureQWACProcess.getQWACType());
        assertEquals(Indication.PASSED, signatureQWACProcess.getConclusion().getIndication());

        // 2-qwac checks
        boolean certPolicyCheckPresent = false;
        boolean certQualConclusiveCheckPresent = false;
        boolean wsaCheckAtIssuanceTimePresent = false;
        boolean wsaCheckAtValidationTimePresent = false;
        boolean certValidityPeriodCheckPresent = false;
        boolean domainNamePresent = false;
        boolean extKeyUsageCheckPresent = false;
        boolean bbbCheckConclusive = false;
        boolean is2QWACProcessPresent = false;
        for (XmlValidationQWACProcess xmlValidationQWACProcess : signatureQWACProcess.getValidationQWACProcess()) {
            if (i18nProvider.getMessage(MessageTag.QWAC_VALIDATION_PROFILE,
                    ValidationProcessUtils.getQWACValidationMessageTag(QWACProfile.QWAC_2)).equals(xmlValidationQWACProcess.getTitle())) {
                assertEquals(Indication.PASSED, xmlValidationQWACProcess.getConclusion().getIndication());
                for (XmlConstraint xmlConstraint : xmlValidationQWACProcess.getConstraint()) {
                    assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                    if (MessageTag.QWAC_CERT_POLICY.getId().equals(xmlConstraint.getName().getKey())) {
                        certPolicyCheckPresent = true;
                    } else if (MessageTag.QWAC_CERT_QUAL_CONCLUSIVE.getId().equals(xmlConstraint.getName().getKey())) {
                        certQualConclusiveCheckPresent = true;
                    } else if (MessageTag.QWAC_IS_WSA_AT_TIME.getId().equals(xmlConstraint.getName().getKey())) {
                        if (i18nProvider.getMessage(MessageTag.QWAC_IS_WSA_AT_TIME, ValidationProcessUtils.getValidationTimeMessageTag(
                                ValidationTime.CERTIFICATE_ISSUANCE_TIME)).equals(xmlConstraint.getName().getValue())) {
                            wsaCheckAtIssuanceTimePresent = true;
                        } else if (i18nProvider.getMessage(MessageTag.QWAC_IS_WSA_AT_TIME, ValidationProcessUtils.getValidationTimeMessageTag(
                                ValidationTime.VALIDATION_TIME)).equals(xmlConstraint.getName().getValue())) {
                            wsaCheckAtValidationTimePresent = true;
                        }
                    } else if (MessageTag.QWAC_VAL_PERIOD.getId().equals(xmlConstraint.getName().getKey())) {
                        certValidityPeriodCheckPresent = true;
                    } else if (MessageTag.QWAC_DOMAIN_NAME.getId().equals(xmlConstraint.getName().getKey())) {
                        domainNamePresent = true;
                    } else if (MessageTag.QWAC2_EXT_KEY_USAGE.getId().equals(xmlConstraint.getName().getKey())) {
                        extKeyUsageCheckPresent = true;
                    } else if (MessageTag.BBB_ACCEPT.getId().equals(xmlConstraint.getName().getKey())) {
                        bbbCheckConclusive = true;
                    }
                }

                is2QWACProcessPresent = true;
            }
        }
        assertTrue(certPolicyCheckPresent);
        assertTrue(certQualConclusiveCheckPresent);
        assertTrue(wsaCheckAtIssuanceTimePresent);
        assertTrue(wsaCheckAtValidationTimePresent);
        assertTrue(certValidityPeriodCheckPresent);
        assertTrue(domainNamePresent);
        assertTrue(extKeyUsageCheckPresent);
        assertTrue(bbbCheckConclusive);
        assertTrue(is2QWACProcessPresent);

        checkReports(reports);
    }

    @Test
    void tlsNoBindingTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/qwac-validation/2-qwac-valid-diag-data.xml"));
        assertNotNull(diagnosticData);

        XmlSignature signature = diagnosticData.getSignatures().get(0);
        for (XmlDigestMatcher xmlDigestMatcher : signature.getDigestMatchers()) {
            xmlDigestMatcher.setDocumentName(null);
        }

        String certificateId = "C-83D242F9A51C7A62BA1B774268EAAECBAB097479E83D8675C14F02DFB269FE77";

        QWACCertificateProcessExecutor executor = new QWACCertificateProcessExecutor();
        executor.setCertificateId(certificateId);
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        CertificateReports reports = executor.execute();

        SimpleCertificateReport simpleReport = reports.getSimpleReport();
        assertNotNull(simpleReport);

        assertEquals(QWACProfile.NOT_QWAC, simpleReport.getQWACProfile());
        assertEquals(QWACProfile.QWAC_2, simpleReport.getTLSBindingSignatureIssuerCertificateQWACProfile());

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(QWACProfile.NOT_QWAC, detailedReport.getCertificateQWACProfile(certificateId));

        XmlCertificate xmlCertificate = detailedReport.getXmlCertificateById(certificateId);
        assertNotNull(xmlCertificate);

        XmlQWACProcess qwacProcess = xmlCertificate.getQWACProcess();
        assertNotNull(qwacProcess);
        assertEquals(certificateId, qwacProcess.getId());
        assertEquals(QWACProfile.NOT_QWAC, qwacProcess.getQWACType());
        assertEquals(Indication.FAILED, qwacProcess.getConclusion().getIndication());

        boolean isQWACValidCheckFound = false;
        for (XmlConstraint xmlConstraint : qwacProcess.getConstraint()) {
            if (MessageTag.QWAC_VALID.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                assertEquals(MessageTag.QWAC_VALID_ANS.getId(), xmlConstraint.getError().getKey());
                isQWACValidCheckFound = true;
            }
        }
        assertTrue(isQWACValidCheckFound);

        // 1-qwac checks
        boolean is1QWACProcessPresent = false;
        boolean bbbCheckPresent = false;
        boolean qwac1DomainNamePresent = false;
        boolean linkHeaderPresent = false;
        boolean sigFormCheckPresent = false;
        boolean jadesCheckPresent = false;
        boolean jadesCompactCheckPresent = false;
        boolean expTimeCheckPresent = false;
        boolean sigExpCheckPresent = false;
        boolean qwac2CheckPresent = false;
        boolean sigValidCheckPresent = false;
        boolean tlsCertBindingValidCheckPresent = false;

        boolean isTlsSupportedBy2QWACProcessPresent = false;
        for (XmlValidationQWACProcess xmlValidationQWACProcess : qwacProcess.getValidationQWACProcess()) {
            if (i18nProvider.getMessage(MessageTag.QWAC_VALIDATION_PROFILE,
                    ValidationProcessUtils.getQWACValidationMessageTag(QWACProfile.QWAC_1)).equals(xmlValidationQWACProcess.getTitle())) {
                assertEquals(Indication.FAILED, xmlValidationQWACProcess.getConclusion().getIndication());
                is1QWACProcessPresent = true;

            } else if (i18nProvider.getMessage(MessageTag.QWAC_VALIDATION_PROFILE,
                    ValidationProcessUtils.getQWACValidationMessageTag(QWACProfile.TLS_BY_QWAC_2)).equals(xmlValidationQWACProcess.getTitle())) {
                assertEquals(Indication.FAILED, xmlValidationQWACProcess.getConclusion().getIndication());
                for (XmlConstraint xmlConstraint : xmlValidationQWACProcess.getConstraint()) {
                    if (MessageTag.BBB_ACCEPT.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        bbbCheckPresent = true;
                    } else if (MessageTag.QWAC_DOMAIN_NAME.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        qwac1DomainNamePresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_URL.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        linkHeaderPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        sigFormCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG_FORM.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        jadesCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG_SER.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        jadesCompactCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG_EXP.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        expTimeCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG_EXPIRY_DATE.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        sigExpCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_QWAC2.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        qwac2CheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG_VALID.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        sigValidCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_CERT_IDENTIFIED.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                        assertEquals(MessageTag.TLS_CERT_BINDING_CERT_IDENTIFIED_ANS.getId(), xmlConstraint.getError().getKey());
                        tlsCertBindingValidCheckPresent = true;
                    }
                }

                isTlsSupportedBy2QWACProcessPresent = true;
            }
        }
        assertTrue(is1QWACProcessPresent);
        assertTrue(bbbCheckPresent);
        assertTrue(qwac1DomainNamePresent);
        assertTrue(linkHeaderPresent);
        assertTrue(sigFormCheckPresent);
        assertTrue(jadesCheckPresent);
        assertTrue(jadesCompactCheckPresent);
        assertTrue(expTimeCheckPresent);
        assertTrue(sigExpCheckPresent);
        assertTrue(qwac2CheckPresent);
        assertTrue(sigValidCheckPresent);
        assertTrue(tlsCertBindingValidCheckPresent);
        assertTrue(isTlsSupportedBy2QWACProcessPresent);

        XmlSignature tlsCertificateBindingSignature = diagnosticData
                .getConnectionInfo().getTLSCertificateBindingSignature().getSignature();

        XmlBasicBuildingBlocks sigBBB = detailedReport.getBasicBuildingBlockById(tlsCertificateBindingSignature.getId());
        assertNotNull(sigBBB);
        assertEquals(Indication.PASSED, sigBBB.getConclusion().getIndication());

        XmlSAV xmlSAV = sigBBB.getSAV();
        assertNotNull(xmlSAV);
        assertEquals(Indication.PASSED, xmlSAV.getConclusion().getIndication());

        boolean signCertCheckPresent = false;
        boolean signCertOnlyOneCheckPresent = false;
        boolean kidCheckPresent = false;
        boolean signTimeCheckPresent = false;
        boolean ctyCheckPresent = false;
        for (XmlConstraint xmlConstraint : xmlSAV.getConstraint()) {
            assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
            if (MessageTag.BBB_ICS_ISASCP.getId().equals(xmlConstraint.getName().getKey())) {
                signCertCheckPresent = true;
            } else if (MessageTag.BBB_ICS_ISASCPU.getId().equals(xmlConstraint.getName().getKey())) {
                signCertOnlyOneCheckPresent = true;
            } else if (MessageTag.BBB_ICS_ISAKIDP.getId().equals(xmlConstraint.getName().getKey())) {
                kidCheckPresent = true;
            } else if (MessageTag.BBB_SAV_ISQPSTP.getId().equals(xmlConstraint.getName().getKey())) {
                signTimeCheckPresent = true;
            } else if (MessageTag.BBB_SAV_ISQPCTP.getId().equals(xmlConstraint.getName().getKey())) {
                ctyCheckPresent = true;
            }
        }
        assertTrue(signCertCheckPresent);
        assertTrue(signCertOnlyOneCheckPresent);
        assertTrue(kidCheckPresent);
        assertTrue(signTimeCheckPresent);
        assertTrue(ctyCheckPresent);

        eu.europa.esig.dss.diagnostic.jaxb.XmlCertificate signingCertificate =
                tlsCertificateBindingSignature.getSigningCertificate().getCertificate();
        assertEquals(QWACProfile.QWAC_2, detailedReport.getCertificateQWACProfile(signingCertificate.getId()));

        eu.europa.esig.dss.detailedreport.jaxb.XmlSignature xmlSignature = detailedReport.getXmlSignatureById(tlsCertificateBindingSignature.getId());
        assertEquals(Indication.TOTAL_PASSED, xmlSignature.getConclusion().getIndication());

        XmlValidationSignatureQualification signatureQualification = xmlSignature.getValidationSignatureQualification();
        assertEquals(SignatureQualification.NOT_ADES, signatureQualification.getSignatureQualification());

        XmlQWACProcess signatureQWACProcess = signatureQualification.getQWACProcess();
        assertEquals(signingCertificate.getId(), signatureQWACProcess.getId());
        assertEquals(QWACProfile.QWAC_2, signatureQWACProcess.getQWACType());
        assertEquals(Indication.PASSED, signatureQWACProcess.getConclusion().getIndication());

        // 2-qwac checks
        boolean certPolicyCheckPresent = false;
        boolean certQualConclusiveCheckPresent = false;
        boolean wsaCheckAtIssuanceTimePresent = false;
        boolean wsaCheckAtValidationTimePresent = false;
        boolean certValidityPeriodCheckPresent = false;
        boolean domainNamePresent = false;
        boolean extKeyUsageCheckPresent = false;
        boolean bbbCheckConclusive = false;
        boolean is2QWACProcessPresent = false;
        for (XmlValidationQWACProcess xmlValidationQWACProcess : signatureQWACProcess.getValidationQWACProcess()) {
            if (i18nProvider.getMessage(MessageTag.QWAC_VALIDATION_PROFILE,
                    ValidationProcessUtils.getQWACValidationMessageTag(QWACProfile.QWAC_2)).equals(xmlValidationQWACProcess.getTitle())) {
                assertEquals(Indication.PASSED, xmlValidationQWACProcess.getConclusion().getIndication());
                for (XmlConstraint xmlConstraint : xmlValidationQWACProcess.getConstraint()) {
                    assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                    if (MessageTag.QWAC_CERT_POLICY.getId().equals(xmlConstraint.getName().getKey())) {
                        certPolicyCheckPresent = true;
                    } else if (MessageTag.QWAC_CERT_QUAL_CONCLUSIVE.getId().equals(xmlConstraint.getName().getKey())) {
                        certQualConclusiveCheckPresent = true;
                    } else if (MessageTag.QWAC_IS_WSA_AT_TIME.getId().equals(xmlConstraint.getName().getKey())) {
                        if (i18nProvider.getMessage(MessageTag.QWAC_IS_WSA_AT_TIME, ValidationProcessUtils.getValidationTimeMessageTag(
                                ValidationTime.CERTIFICATE_ISSUANCE_TIME)).equals(xmlConstraint.getName().getValue())) {
                            wsaCheckAtIssuanceTimePresent = true;
                        } else if (i18nProvider.getMessage(MessageTag.QWAC_IS_WSA_AT_TIME, ValidationProcessUtils.getValidationTimeMessageTag(
                                ValidationTime.VALIDATION_TIME)).equals(xmlConstraint.getName().getValue())) {
                            wsaCheckAtValidationTimePresent = true;
                        }
                    } else if (MessageTag.QWAC_VAL_PERIOD.getId().equals(xmlConstraint.getName().getKey())) {
                        certValidityPeriodCheckPresent = true;
                    } else if (MessageTag.QWAC_DOMAIN_NAME.getId().equals(xmlConstraint.getName().getKey())) {
                        domainNamePresent = true;
                    } else if (MessageTag.QWAC2_EXT_KEY_USAGE.getId().equals(xmlConstraint.getName().getKey())) {
                        extKeyUsageCheckPresent = true;
                    } else if (MessageTag.BBB_ACCEPT.getId().equals(xmlConstraint.getName().getKey())) {
                        bbbCheckConclusive = true;
                    }
                }

                is2QWACProcessPresent = true;
            }
        }
        assertTrue(certPolicyCheckPresent);
        assertTrue(certQualConclusiveCheckPresent);
        assertTrue(wsaCheckAtIssuanceTimePresent);
        assertTrue(wsaCheckAtValidationTimePresent);
        assertTrue(certValidityPeriodCheckPresent);
        assertTrue(domainNamePresent);
        assertTrue(extKeyUsageCheckPresent);
        assertTrue(bbbCheckConclusive);
        assertTrue(is2QWACProcessPresent);

        checkReports(reports);
    }

    @Test
    void bindingCertDigestNoMatchTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/qwac-validation/2-qwac-valid-diag-data.xml"));
        assertNotNull(diagnosticData);

        XmlSignature signature = diagnosticData.getSignatures().get(0);
        XmlDigestMatcher sigDEntry = signature.getDigestMatchers().get(1);
        sigDEntry.setDataIntact(false);

        String certificateId = "C-83D242F9A51C7A62BA1B774268EAAECBAB097479E83D8675C14F02DFB269FE77";

        QWACCertificateProcessExecutor executor = new QWACCertificateProcessExecutor();
        executor.setCertificateId(certificateId);
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        CertificateReports reports = executor.execute();

        SimpleCertificateReport simpleReport = reports.getSimpleReport();
        assertNotNull(simpleReport);

        assertEquals(QWACProfile.NOT_QWAC, simpleReport.getQWACProfile());
        assertEquals(QWACProfile.QWAC_2, simpleReport.getTLSBindingSignatureIssuerCertificateQWACProfile());

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(QWACProfile.NOT_QWAC, detailedReport.getCertificateQWACProfile(certificateId));

        XmlCertificate xmlCertificate = detailedReport.getXmlCertificateById(certificateId);
        assertNotNull(xmlCertificate);

        XmlQWACProcess qwacProcess = xmlCertificate.getQWACProcess();
        assertNotNull(qwacProcess);
        assertEquals(certificateId, qwacProcess.getId());
        assertEquals(QWACProfile.NOT_QWAC, qwacProcess.getQWACType());
        assertEquals(Indication.FAILED, qwacProcess.getConclusion().getIndication());

        boolean isQWACValidCheckFound = false;
        for (XmlConstraint xmlConstraint : qwacProcess.getConstraint()) {
            if (MessageTag.QWAC_VALID.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                assertEquals(MessageTag.QWAC_VALID_ANS.getId(), xmlConstraint.getError().getKey());
                isQWACValidCheckFound = true;
            }
        }
        assertTrue(isQWACValidCheckFound);

        // 1-qwac checks
        boolean is1QWACProcessPresent = false;
        boolean bbbCheckPresent = false;
        boolean qwac1DomainNamePresent = false;
        boolean linkHeaderPresent = false;
        boolean sigFormCheckPresent = false;
        boolean jadesCheckPresent = false;
        boolean jadesCompactCheckPresent = false;
        boolean expTimeCheckPresent = false;
        boolean sigExpCheckPresent = false;
        boolean qwac2CheckPresent = false;
        boolean sigValidCheckPresent = false;
        boolean tlsCertBindingValidCheckPresent = false;

        boolean isTlsSupportedBy2QWACProcessPresent = false;
        for (XmlValidationQWACProcess xmlValidationQWACProcess : qwacProcess.getValidationQWACProcess()) {
            if (i18nProvider.getMessage(MessageTag.QWAC_VALIDATION_PROFILE,
                    ValidationProcessUtils.getQWACValidationMessageTag(QWACProfile.QWAC_1)).equals(xmlValidationQWACProcess.getTitle())) {
                assertEquals(Indication.FAILED, xmlValidationQWACProcess.getConclusion().getIndication());
                is1QWACProcessPresent = true;

            } else if (i18nProvider.getMessage(MessageTag.QWAC_VALIDATION_PROFILE,
                    ValidationProcessUtils.getQWACValidationMessageTag(QWACProfile.TLS_BY_QWAC_2)).equals(xmlValidationQWACProcess.getTitle())) {
                assertEquals(Indication.FAILED, xmlValidationQWACProcess.getConclusion().getIndication());
                for (XmlConstraint xmlConstraint : xmlValidationQWACProcess.getConstraint()) {
                    if (MessageTag.BBB_ACCEPT.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        bbbCheckPresent = true;
                    } else if (MessageTag.QWAC_DOMAIN_NAME.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        qwac1DomainNamePresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_URL.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        linkHeaderPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        sigFormCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG_FORM.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        jadesCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG_SER.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        jadesCompactCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG_EXP.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        expTimeCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG_EXPIRY_DATE.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        sigExpCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_QWAC2.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        qwac2CheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG_VALID.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        sigValidCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_CERT_IDENTIFIED.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                        assertEquals(MessageTag.TLS_CERT_BINDING_CERT_IDENTIFIED_ANS.getId(), xmlConstraint.getError().getKey());
                        tlsCertBindingValidCheckPresent = true;
                    }
                }

                isTlsSupportedBy2QWACProcessPresent = true;
            }
        }
        assertTrue(is1QWACProcessPresent);
        assertTrue(bbbCheckPresent);
        assertTrue(qwac1DomainNamePresent);
        assertTrue(linkHeaderPresent);
        assertTrue(sigFormCheckPresent);
        assertTrue(jadesCheckPresent);
        assertTrue(jadesCompactCheckPresent);
        assertTrue(expTimeCheckPresent);
        assertTrue(sigExpCheckPresent);
        assertTrue(qwac2CheckPresent);
        assertTrue(sigValidCheckPresent);
        assertTrue(tlsCertBindingValidCheckPresent);
        assertTrue(isTlsSupportedBy2QWACProcessPresent);

        XmlSignature tlsCertificateBindingSignature = diagnosticData
                .getConnectionInfo().getTLSCertificateBindingSignature().getSignature();

        XmlBasicBuildingBlocks sigBBB = detailedReport.getBasicBuildingBlockById(tlsCertificateBindingSignature.getId());
        assertNotNull(sigBBB);
        assertEquals(Indication.PASSED, sigBBB.getConclusion().getIndication());

        XmlSAV xmlSAV = sigBBB.getSAV();
        assertNotNull(xmlSAV);
        assertEquals(Indication.PASSED, xmlSAV.getConclusion().getIndication());

        boolean signCertCheckPresent = false;
        boolean signCertOnlyOneCheckPresent = false;
        boolean kidCheckPresent = false;
        boolean signTimeCheckPresent = false;
        boolean ctyCheckPresent = false;
        for (XmlConstraint xmlConstraint : xmlSAV.getConstraint()) {
            assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
            if (MessageTag.BBB_ICS_ISASCP.getId().equals(xmlConstraint.getName().getKey())) {
                signCertCheckPresent = true;
            } else if (MessageTag.BBB_ICS_ISASCPU.getId().equals(xmlConstraint.getName().getKey())) {
                signCertOnlyOneCheckPresent = true;
            } else if (MessageTag.BBB_ICS_ISAKIDP.getId().equals(xmlConstraint.getName().getKey())) {
                kidCheckPresent = true;
            } else if (MessageTag.BBB_SAV_ISQPSTP.getId().equals(xmlConstraint.getName().getKey())) {
                signTimeCheckPresent = true;
            } else if (MessageTag.BBB_SAV_ISQPCTP.getId().equals(xmlConstraint.getName().getKey())) {
                ctyCheckPresent = true;
            }
        }
        assertTrue(signCertCheckPresent);
        assertTrue(signCertOnlyOneCheckPresent);
        assertTrue(kidCheckPresent);
        assertTrue(signTimeCheckPresent);
        assertTrue(ctyCheckPresent);

        eu.europa.esig.dss.diagnostic.jaxb.XmlCertificate signingCertificate =
                tlsCertificateBindingSignature.getSigningCertificate().getCertificate();
        assertEquals(QWACProfile.QWAC_2, detailedReport.getCertificateQWACProfile(signingCertificate.getId()));

        eu.europa.esig.dss.detailedreport.jaxb.XmlSignature xmlSignature = detailedReport.getXmlSignatureById(tlsCertificateBindingSignature.getId());
        assertEquals(Indication.TOTAL_PASSED, xmlSignature.getConclusion().getIndication());

        XmlValidationSignatureQualification signatureQualification = xmlSignature.getValidationSignatureQualification();
        assertEquals(SignatureQualification.NOT_ADES, signatureQualification.getSignatureQualification());

        XmlQWACProcess signatureQWACProcess = signatureQualification.getQWACProcess();
        assertEquals(signingCertificate.getId(), signatureQWACProcess.getId());
        assertEquals(QWACProfile.QWAC_2, signatureQWACProcess.getQWACType());
        assertEquals(Indication.PASSED, signatureQWACProcess.getConclusion().getIndication());

        // 2-qwac checks
        boolean certPolicyCheckPresent = false;
        boolean certQualConclusiveCheckPresent = false;
        boolean wsaCheckAtIssuanceTimePresent = false;
        boolean wsaCheckAtValidationTimePresent = false;
        boolean certValidityPeriodCheckPresent = false;
        boolean domainNamePresent = false;
        boolean extKeyUsageCheckPresent = false;
        boolean bbbCheckConclusive = false;
        boolean is2QWACProcessPresent = false;
        for (XmlValidationQWACProcess xmlValidationQWACProcess : signatureQWACProcess.getValidationQWACProcess()) {
            if (i18nProvider.getMessage(MessageTag.QWAC_VALIDATION_PROFILE,
                    ValidationProcessUtils.getQWACValidationMessageTag(QWACProfile.QWAC_2)).equals(xmlValidationQWACProcess.getTitle())) {
                assertEquals(Indication.PASSED, xmlValidationQWACProcess.getConclusion().getIndication());
                for (XmlConstraint xmlConstraint : xmlValidationQWACProcess.getConstraint()) {
                    assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                    if (MessageTag.QWAC_CERT_POLICY.getId().equals(xmlConstraint.getName().getKey())) {
                        certPolicyCheckPresent = true;
                    } else if (MessageTag.QWAC_CERT_QUAL_CONCLUSIVE.getId().equals(xmlConstraint.getName().getKey())) {
                        certQualConclusiveCheckPresent = true;
                    } else if (MessageTag.QWAC_IS_WSA_AT_TIME.getId().equals(xmlConstraint.getName().getKey())) {
                        if (i18nProvider.getMessage(MessageTag.QWAC_IS_WSA_AT_TIME, ValidationProcessUtils.getValidationTimeMessageTag(
                                ValidationTime.CERTIFICATE_ISSUANCE_TIME)).equals(xmlConstraint.getName().getValue())) {
                            wsaCheckAtIssuanceTimePresent = true;
                        } else if (i18nProvider.getMessage(MessageTag.QWAC_IS_WSA_AT_TIME, ValidationProcessUtils.getValidationTimeMessageTag(
                                ValidationTime.VALIDATION_TIME)).equals(xmlConstraint.getName().getValue())) {
                            wsaCheckAtValidationTimePresent = true;
                        }
                    } else if (MessageTag.QWAC_VAL_PERIOD.getId().equals(xmlConstraint.getName().getKey())) {
                        certValidityPeriodCheckPresent = true;
                    } else if (MessageTag.QWAC_DOMAIN_NAME.getId().equals(xmlConstraint.getName().getKey())) {
                        domainNamePresent = true;
                    } else if (MessageTag.QWAC2_EXT_KEY_USAGE.getId().equals(xmlConstraint.getName().getKey())) {
                        extKeyUsageCheckPresent = true;
                    } else if (MessageTag.BBB_ACCEPT.getId().equals(xmlConstraint.getName().getKey())) {
                        bbbCheckConclusive = true;
                    }
                }

                is2QWACProcessPresent = true;
            }
        }
        assertTrue(certPolicyCheckPresent);
        assertTrue(certQualConclusiveCheckPresent);
        assertTrue(wsaCheckAtIssuanceTimePresent);
        assertTrue(wsaCheckAtValidationTimePresent);
        assertTrue(certValidityPeriodCheckPresent);
        assertTrue(domainNamePresent);
        assertTrue(extKeyUsageCheckPresent);
        assertTrue(bbbCheckConclusive);
        assertTrue(is2QWACProcessPresent);

        checkReports(reports);
    }

    // This test should ignore not matching certificates
    @Test
    void oneRefNoMatchValidTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/qwac-validation/2-qwac-valid-diag-data.xml"));
        assertNotNull(diagnosticData);

        XmlDigestMatcher xmlDigestMatcher = new XmlDigestMatcher();
        xmlDigestMatcher.setType(DigestMatcherType.SIG_D_ENTRY);
        xmlDigestMatcher.setUri("TLSCertificate_2");
        eu.europa.esig.dss.diagnostic.jaxb.XmlCertificate otherCertificate =
                diagnosticData.getSignatures().get(0).getSigningCertificate().getCertificate();
        xmlDigestMatcher.setDigestMethod(otherCertificate.getDigestAlgoAndValue().getDigestMethod());
        xmlDigestMatcher.setDigestValue(otherCertificate.getDigestAlgoAndValue().getDigestValue());
        xmlDigestMatcher.setDataFound(false);
        xmlDigestMatcher.setDataIntact(false);

        diagnosticData.getSignatures().get(0).getDigestMatchers().add(xmlDigestMatcher);

        String certificateId = "C-83D242F9A51C7A62BA1B774268EAAECBAB097479E83D8675C14F02DFB269FE77";

        QWACCertificateProcessExecutor executor = new QWACCertificateProcessExecutor();
        executor.setCertificateId(certificateId);
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        CertificateReports reports = executor.execute();

        SimpleCertificateReport simpleReport = reports.getSimpleReport();
        assertNotNull(simpleReport);

        assertEquals(CertificateQualification.NA, simpleReport.getQualificationAtCertificateIssuance());
        assertTrue(Utils.isCollectionEmpty(simpleReport.getQualificationInfoAtIssuanceTime(certificateId)));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getQualificationWarningsAtIssuanceTime(certificateId)));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getQualificationErrorsAtIssuanceTime(certificateId)));

        assertEquals(CertificateQualification.NA, simpleReport.getQualificationAtValidationTime());
        assertTrue(Utils.isCollectionEmpty(simpleReport.getQualificationInfoAtValidationTime(certificateId)));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getQualificationWarningsAtValidationTime(certificateId)));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getQualificationErrorsAtValidationTime(certificateId)));

        assertEquals(QWACProfile.TLS_BY_QWAC_2, simpleReport.getQWACProfile());

        String bindingSignatureIssuerId = simpleReport.getTLSBindingSignatureIssuerCertificate().getId();
        assertEquals(CertificateQualification.QCERT_FOR_WSA, simpleReport.getTLSBindingSignatureIssuerQualificationAtCertificateIssuance());
        assertTrue(Utils.isCollectionEmpty(simpleReport.getQualificationInfoAtIssuanceTime(bindingSignatureIssuerId)));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getQualificationWarningsAtIssuanceTime(bindingSignatureIssuerId)));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getQualificationErrorsAtIssuanceTime(bindingSignatureIssuerId)));

        assertEquals(CertificateQualification.QCERT_FOR_WSA, simpleReport.getTLSBindingSignatureIssuerQualificationAtValidationTime());
        assertTrue(Utils.isCollectionEmpty(simpleReport.getQualificationInfoAtValidationTime(bindingSignatureIssuerId)));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getQualificationWarningsAtValidationTime(bindingSignatureIssuerId)));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getQualificationErrorsAtValidationTime(bindingSignatureIssuerId)));
        assertEquals(QWACProfile.QWAC_2, simpleReport.getTLSBindingSignatureIssuerCertificateQWACProfile());

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(QWACProfile.TLS_BY_QWAC_2, detailedReport.getCertificateQWACProfile(certificateId));

        XmlCertificate xmlCertificate = detailedReport.getXmlCertificateById(certificateId);
        assertNotNull(xmlCertificate);

        XmlQWACProcess qwacProcess = xmlCertificate.getQWACProcess();
        assertNotNull(qwacProcess);
        assertEquals(certificateId, qwacProcess.getId());
        assertEquals(QWACProfile.TLS_BY_QWAC_2, qwacProcess.getQWACType());
        assertEquals(Indication.PASSED, qwacProcess.getConclusion().getIndication());

        boolean isQWACValidCheckFound = false;
        for (XmlConstraint xmlConstraint : qwacProcess.getConstraint()) {
            if (MessageTag.QWAC_VALID.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                isQWACValidCheckFound = true;
            }
        }
        assertTrue(isQWACValidCheckFound);

        // 1-qwac checks
        boolean is1QWACProcessPresent = false;
        boolean bbbCheckPresent = false;
        boolean qwac1DomainNamePresent = false;
        boolean linkHeaderPresent = false;
        boolean sigFormCheckPresent = false;
        boolean jadesCheckPresent = false;
        boolean jadesCompactCheckPresent = false;
        boolean expTimeCheckPresent = false;
        boolean sigExpCheckPresent = false;
        boolean qwac2CheckPresent = false;
        boolean sigValidCheckPresent = false;
        boolean tlsCertBindingValidCheckPresent = false;

        boolean isTlsSupportedBy2QWACProcessPresent = false;
        for (XmlValidationQWACProcess xmlValidationQWACProcess : qwacProcess.getValidationQWACProcess()) {
            if (i18nProvider.getMessage(MessageTag.QWAC_VALIDATION_PROFILE,
                    ValidationProcessUtils.getQWACValidationMessageTag(QWACProfile.QWAC_1)).equals(xmlValidationQWACProcess.getTitle())) {
                assertEquals(Indication.FAILED, xmlValidationQWACProcess.getConclusion().getIndication());
                is1QWACProcessPresent = true;

            } else if (i18nProvider.getMessage(MessageTag.QWAC_VALIDATION_PROFILE,
                    ValidationProcessUtils.getQWACValidationMessageTag(QWACProfile.TLS_BY_QWAC_2)).equals(xmlValidationQWACProcess.getTitle())) {
                assertEquals(Indication.PASSED, xmlValidationQWACProcess.getConclusion().getIndication());
                for (XmlConstraint xmlConstraint : xmlValidationQWACProcess.getConstraint()) {
                    assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                    if (MessageTag.BBB_ACCEPT.getId().equals(xmlConstraint.getName().getKey())) {
                        bbbCheckPresent = true;
                    } else if (MessageTag.QWAC_DOMAIN_NAME.getId().equals(xmlConstraint.getName().getKey())) {
                        qwac1DomainNamePresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_URL.getId().equals(xmlConstraint.getName().getKey())) {
                        linkHeaderPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG.getId().equals(xmlConstraint.getName().getKey())) {
                        sigFormCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG_FORM.getId().equals(xmlConstraint.getName().getKey())) {
                        jadesCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG_SER.getId().equals(xmlConstraint.getName().getKey())) {
                        jadesCompactCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG_EXP.getId().equals(xmlConstraint.getName().getKey())) {
                        expTimeCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG_EXPIRY_DATE.getId().equals(xmlConstraint.getName().getKey())) {
                        sigExpCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_QWAC2.getId().equals(xmlConstraint.getName().getKey())) {
                        qwac2CheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG_VALID.getId().equals(xmlConstraint.getName().getKey())) {
                        sigValidCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_CERT_IDENTIFIED.getId().equals(xmlConstraint.getName().getKey())) {
                        tlsCertBindingValidCheckPresent = true;
                    }
                }

                isTlsSupportedBy2QWACProcessPresent = true;
            }
        }
        assertTrue(is1QWACProcessPresent);
        assertTrue(bbbCheckPresent);
        assertTrue(qwac1DomainNamePresent);
        assertTrue(linkHeaderPresent);
        assertTrue(sigFormCheckPresent);
        assertTrue(jadesCheckPresent);
        assertTrue(jadesCompactCheckPresent);
        assertTrue(expTimeCheckPresent);
        assertTrue(sigExpCheckPresent);
        assertTrue(qwac2CheckPresent);
        assertTrue(sigValidCheckPresent);
        assertTrue(tlsCertBindingValidCheckPresent);
        assertTrue(isTlsSupportedBy2QWACProcessPresent);

        XmlSignature tlsCertificateBindingSignature = diagnosticData
                .getConnectionInfo().getTLSCertificateBindingSignature().getSignature();

        XmlBasicBuildingBlocks sigBBB = detailedReport.getBasicBuildingBlockById(tlsCertificateBindingSignature.getId());
        assertNotNull(sigBBB);
        assertEquals(Indication.PASSED, sigBBB.getConclusion().getIndication());

        XmlSAV xmlSAV = sigBBB.getSAV();
        assertNotNull(xmlSAV);
        assertEquals(Indication.PASSED, xmlSAV.getConclusion().getIndication());

        boolean signCertCheckPresent = false;
        boolean signCertOnlyOneCheckPresent = false;
        boolean kidCheckPresent = false;
        boolean signTimeCheckPresent = false;
        boolean ctyCheckPresent = false;
        for (XmlConstraint xmlConstraint : xmlSAV.getConstraint()) {
            assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
            if (MessageTag.BBB_ICS_ISASCP.getId().equals(xmlConstraint.getName().getKey())) {
                signCertCheckPresent = true;
            } else if (MessageTag.BBB_ICS_ISASCPU.getId().equals(xmlConstraint.getName().getKey())) {
                signCertOnlyOneCheckPresent = true;
            } else if (MessageTag.BBB_ICS_ISAKIDP.getId().equals(xmlConstraint.getName().getKey())) {
                kidCheckPresent = true;
            } else if (MessageTag.BBB_SAV_ISQPSTP.getId().equals(xmlConstraint.getName().getKey())) {
                signTimeCheckPresent = true;
            } else if (MessageTag.BBB_SAV_ISQPCTP.getId().equals(xmlConstraint.getName().getKey())) {
                ctyCheckPresent = true;
            }
        }
        assertTrue(signCertCheckPresent);
        assertTrue(signCertOnlyOneCheckPresent);
        assertTrue(kidCheckPresent);
        assertTrue(signTimeCheckPresent);
        assertTrue(ctyCheckPresent);

        eu.europa.esig.dss.diagnostic.jaxb.XmlCertificate signingCertificate =
                tlsCertificateBindingSignature.getSigningCertificate().getCertificate();
        assertEquals(QWACProfile.QWAC_2, detailedReport.getCertificateQWACProfile(signingCertificate.getId()));

        eu.europa.esig.dss.detailedreport.jaxb.XmlSignature xmlSignature = detailedReport.getXmlSignatureById(tlsCertificateBindingSignature.getId());
        assertEquals(Indication.TOTAL_PASSED, xmlSignature.getConclusion().getIndication());

        XmlValidationSignatureQualification signatureQualification = xmlSignature.getValidationSignatureQualification();
        assertEquals(SignatureQualification.NOT_ADES, signatureQualification.getSignatureQualification());

        XmlQWACProcess signatureQWACProcess = signatureQualification.getQWACProcess();
        assertEquals(signingCertificate.getId(), signatureQWACProcess.getId());
        assertEquals(QWACProfile.QWAC_2, signatureQWACProcess.getQWACType());
        assertEquals(Indication.PASSED, signatureQWACProcess.getConclusion().getIndication());

        // 2-qwac checks
        boolean certPolicyCheckPresent = false;
        boolean certQualConclusiveCheckPresent = false;
        boolean wsaCheckAtIssuanceTimePresent = false;
        boolean wsaCheckAtValidationTimePresent = false;
        boolean certValidityPeriodCheckPresent = false;
        boolean domainNamePresent = false;
        boolean extKeyUsageCheckPresent = false;
        boolean bbbCheckConclusive = false;
        boolean is2QWACProcessPresent = false;
        for (XmlValidationQWACProcess xmlValidationQWACProcess : signatureQWACProcess.getValidationQWACProcess()) {
            if (i18nProvider.getMessage(MessageTag.QWAC_VALIDATION_PROFILE,
                    ValidationProcessUtils.getQWACValidationMessageTag(QWACProfile.QWAC_2)).equals(xmlValidationQWACProcess.getTitle())) {
                assertEquals(Indication.PASSED, xmlValidationQWACProcess.getConclusion().getIndication());
                for (XmlConstraint xmlConstraint : xmlValidationQWACProcess.getConstraint()) {
                    assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                    if (MessageTag.QWAC_CERT_POLICY.getId().equals(xmlConstraint.getName().getKey())) {
                        certPolicyCheckPresent = true;
                    } else if (MessageTag.QWAC_CERT_QUAL_CONCLUSIVE.getId().equals(xmlConstraint.getName().getKey())) {
                        certQualConclusiveCheckPresent = true;
                    } else if (MessageTag.QWAC_IS_WSA_AT_TIME.getId().equals(xmlConstraint.getName().getKey())) {
                        if (i18nProvider.getMessage(MessageTag.QWAC_IS_WSA_AT_TIME, ValidationProcessUtils.getValidationTimeMessageTag(
                                ValidationTime.CERTIFICATE_ISSUANCE_TIME)).equals(xmlConstraint.getName().getValue())) {
                            wsaCheckAtIssuanceTimePresent = true;
                        } else if (i18nProvider.getMessage(MessageTag.QWAC_IS_WSA_AT_TIME, ValidationProcessUtils.getValidationTimeMessageTag(
                                ValidationTime.VALIDATION_TIME)).equals(xmlConstraint.getName().getValue())) {
                            wsaCheckAtValidationTimePresent = true;
                        }
                    } else if (MessageTag.QWAC_VAL_PERIOD.getId().equals(xmlConstraint.getName().getKey())) {
                        certValidityPeriodCheckPresent = true;
                    } else if (MessageTag.QWAC_DOMAIN_NAME.getId().equals(xmlConstraint.getName().getKey())) {
                        domainNamePresent = true;
                    } else if (MessageTag.QWAC2_EXT_KEY_USAGE.getId().equals(xmlConstraint.getName().getKey())) {
                        extKeyUsageCheckPresent = true;
                    } else if (MessageTag.BBB_ACCEPT.getId().equals(xmlConstraint.getName().getKey())) {
                        bbbCheckConclusive = true;
                    }
                }

                is2QWACProcessPresent = true;
            }
        }
        assertTrue(certPolicyCheckPresent);
        assertTrue(certQualConclusiveCheckPresent);
        assertTrue(wsaCheckAtIssuanceTimePresent);
        assertTrue(wsaCheckAtValidationTimePresent);
        assertTrue(certValidityPeriodCheckPresent);
        assertTrue(domainNamePresent);
        assertTrue(extKeyUsageCheckPresent);
        assertTrue(bbbCheckConclusive);
        assertTrue(is2QWACProcessPresent);

        checkReports(reports);
    }

    @Test
    void wrongCertMatchInvalidTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/qwac-validation/2-qwac-valid-diag-data.xml"));
        assertNotNull(diagnosticData);

        eu.europa.esig.dss.diagnostic.jaxb.XmlCertificate otherCertificate =
                diagnosticData.getSignatures().get(0).getSigningCertificate().getCertificate();
        diagnosticData.getSignatures().get(0).getDigestMatchers().get(1).setDocumentName(otherCertificate.getId());

        String certificateId = "C-83D242F9A51C7A62BA1B774268EAAECBAB097479E83D8675C14F02DFB269FE77";

        QWACCertificateProcessExecutor executor = new QWACCertificateProcessExecutor();
        executor.setCertificateId(certificateId);
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        CertificateReports reports = executor.execute();

        SimpleCertificateReport simpleReport = reports.getSimpleReport();
        assertNotNull(simpleReport);

        assertEquals(QWACProfile.NOT_QWAC, simpleReport.getQWACProfile());
        assertEquals(QWACProfile.QWAC_2, simpleReport.getTLSBindingSignatureIssuerCertificateQWACProfile());

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(QWACProfile.NOT_QWAC, detailedReport.getCertificateQWACProfile(certificateId));

        XmlCertificate xmlCertificate = detailedReport.getXmlCertificateById(certificateId);
        assertNotNull(xmlCertificate);

        XmlQWACProcess qwacProcess = xmlCertificate.getQWACProcess();
        assertNotNull(qwacProcess);
        assertEquals(certificateId, qwacProcess.getId());
        assertEquals(QWACProfile.NOT_QWAC, qwacProcess.getQWACType());
        assertEquals(Indication.FAILED, qwacProcess.getConclusion().getIndication());

        boolean isQWACValidCheckFound = false;
        for (XmlConstraint xmlConstraint : qwacProcess.getConstraint()) {
            if (MessageTag.QWAC_VALID.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                assertEquals(MessageTag.QWAC_VALID_ANS.getId(), xmlConstraint.getError().getKey());
                isQWACValidCheckFound = true;
            }
        }
        assertTrue(isQWACValidCheckFound);

        // 1-qwac checks
        boolean is1QWACProcessPresent = false;
        boolean bbbCheckPresent = false;
        boolean qwac1DomainNamePresent = false;
        boolean linkHeaderPresent = false;
        boolean sigFormCheckPresent = false;
        boolean jadesCheckPresent = false;
        boolean jadesCompactCheckPresent = false;
        boolean expTimeCheckPresent = false;
        boolean sigExpCheckPresent = false;
        boolean qwac2CheckPresent = false;
        boolean sigValidCheckPresent = false;
        boolean tlsCertBindingValidCheckPresent = false;

        boolean isTlsSupportedBy2QWACProcessPresent = false;
        for (XmlValidationQWACProcess xmlValidationQWACProcess : qwacProcess.getValidationQWACProcess()) {
            if (i18nProvider.getMessage(MessageTag.QWAC_VALIDATION_PROFILE,
                    ValidationProcessUtils.getQWACValidationMessageTag(QWACProfile.QWAC_1)).equals(xmlValidationQWACProcess.getTitle())) {
                assertEquals(Indication.FAILED, xmlValidationQWACProcess.getConclusion().getIndication());
                is1QWACProcessPresent = true;

            } else if (i18nProvider.getMessage(MessageTag.QWAC_VALIDATION_PROFILE,
                    ValidationProcessUtils.getQWACValidationMessageTag(QWACProfile.TLS_BY_QWAC_2)).equals(xmlValidationQWACProcess.getTitle())) {
                assertEquals(Indication.FAILED, xmlValidationQWACProcess.getConclusion().getIndication());
                for (XmlConstraint xmlConstraint : xmlValidationQWACProcess.getConstraint()) {
                    if (MessageTag.BBB_ACCEPT.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        bbbCheckPresent = true;
                    } else if (MessageTag.QWAC_DOMAIN_NAME.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        qwac1DomainNamePresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_URL.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        linkHeaderPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        sigFormCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG_FORM.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        jadesCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG_SER.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        jadesCompactCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG_EXP.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        expTimeCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG_EXPIRY_DATE.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        sigExpCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_QWAC2.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        qwac2CheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG_VALID.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        sigValidCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_CERT_IDENTIFIED.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                        assertEquals(MessageTag.TLS_CERT_BINDING_CERT_IDENTIFIED_ANS.getId(), xmlConstraint.getError().getKey());
                        tlsCertBindingValidCheckPresent = true;
                    }
                }

                isTlsSupportedBy2QWACProcessPresent = true;
            }
        }
        assertTrue(is1QWACProcessPresent);
        assertTrue(bbbCheckPresent);
        assertTrue(qwac1DomainNamePresent);
        assertTrue(linkHeaderPresent);
        assertTrue(sigFormCheckPresent);
        assertTrue(jadesCheckPresent);
        assertTrue(jadesCompactCheckPresent);
        assertTrue(expTimeCheckPresent);
        assertTrue(sigExpCheckPresent);
        assertTrue(qwac2CheckPresent);
        assertTrue(sigValidCheckPresent);
        assertTrue(tlsCertBindingValidCheckPresent);
        assertTrue(isTlsSupportedBy2QWACProcessPresent);

        XmlSignature tlsCertificateBindingSignature = diagnosticData
                .getConnectionInfo().getTLSCertificateBindingSignature().getSignature();

        XmlBasicBuildingBlocks sigBBB = detailedReport.getBasicBuildingBlockById(tlsCertificateBindingSignature.getId());
        assertNotNull(sigBBB);
        assertEquals(Indication.PASSED, sigBBB.getConclusion().getIndication());

        XmlSAV xmlSAV = sigBBB.getSAV();
        assertNotNull(xmlSAV);
        assertEquals(Indication.PASSED, xmlSAV.getConclusion().getIndication());

        boolean signCertCheckPresent = false;
        boolean signCertOnlyOneCheckPresent = false;
        boolean kidCheckPresent = false;
        boolean signTimeCheckPresent = false;
        boolean ctyCheckPresent = false;
        for (XmlConstraint xmlConstraint : xmlSAV.getConstraint()) {
            assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
            if (MessageTag.BBB_ICS_ISASCP.getId().equals(xmlConstraint.getName().getKey())) {
                signCertCheckPresent = true;
            } else if (MessageTag.BBB_ICS_ISASCPU.getId().equals(xmlConstraint.getName().getKey())) {
                signCertOnlyOneCheckPresent = true;
            } else if (MessageTag.BBB_ICS_ISAKIDP.getId().equals(xmlConstraint.getName().getKey())) {
                kidCheckPresent = true;
            } else if (MessageTag.BBB_SAV_ISQPSTP.getId().equals(xmlConstraint.getName().getKey())) {
                signTimeCheckPresent = true;
            } else if (MessageTag.BBB_SAV_ISQPCTP.getId().equals(xmlConstraint.getName().getKey())) {
                ctyCheckPresent = true;
            }
        }
        assertTrue(signCertCheckPresent);
        assertTrue(signCertOnlyOneCheckPresent);
        assertTrue(kidCheckPresent);
        assertTrue(signTimeCheckPresent);
        assertTrue(ctyCheckPresent);

        eu.europa.esig.dss.diagnostic.jaxb.XmlCertificate signingCertificate =
                tlsCertificateBindingSignature.getSigningCertificate().getCertificate();
        assertEquals(QWACProfile.QWAC_2, detailedReport.getCertificateQWACProfile(signingCertificate.getId()));

        eu.europa.esig.dss.detailedreport.jaxb.XmlSignature xmlSignature = detailedReport.getXmlSignatureById(tlsCertificateBindingSignature.getId());
        assertEquals(Indication.TOTAL_PASSED, xmlSignature.getConclusion().getIndication());

        XmlValidationSignatureQualification signatureQualification = xmlSignature.getValidationSignatureQualification();
        assertEquals(SignatureQualification.NOT_ADES, signatureQualification.getSignatureQualification());

        XmlQWACProcess signatureQWACProcess = signatureQualification.getQWACProcess();
        assertEquals(signingCertificate.getId(), signatureQWACProcess.getId());
        assertEquals(QWACProfile.QWAC_2, signatureQWACProcess.getQWACType());
        assertEquals(Indication.PASSED, signatureQWACProcess.getConclusion().getIndication());

        // 2-qwac checks
        boolean certPolicyCheckPresent = false;
        boolean certQualConclusiveCheckPresent = false;
        boolean wsaCheckAtIssuanceTimePresent = false;
        boolean wsaCheckAtValidationTimePresent = false;
        boolean certValidityPeriodCheckPresent = false;
        boolean domainNamePresent = false;
        boolean extKeyUsageCheckPresent = false;
        boolean bbbCheckConclusive = false;
        boolean is2QWACProcessPresent = false;
        for (XmlValidationQWACProcess xmlValidationQWACProcess : signatureQWACProcess.getValidationQWACProcess()) {
            if (i18nProvider.getMessage(MessageTag.QWAC_VALIDATION_PROFILE,
                    ValidationProcessUtils.getQWACValidationMessageTag(QWACProfile.QWAC_2)).equals(xmlValidationQWACProcess.getTitle())) {
                assertEquals(Indication.PASSED, xmlValidationQWACProcess.getConclusion().getIndication());
                for (XmlConstraint xmlConstraint : xmlValidationQWACProcess.getConstraint()) {
                    assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                    if (MessageTag.QWAC_CERT_POLICY.getId().equals(xmlConstraint.getName().getKey())) {
                        certPolicyCheckPresent = true;
                    } else if (MessageTag.QWAC_CERT_QUAL_CONCLUSIVE.getId().equals(xmlConstraint.getName().getKey())) {
                        certQualConclusiveCheckPresent = true;
                    } else if (MessageTag.QWAC_IS_WSA_AT_TIME.getId().equals(xmlConstraint.getName().getKey())) {
                        if (i18nProvider.getMessage(MessageTag.QWAC_IS_WSA_AT_TIME, ValidationProcessUtils.getValidationTimeMessageTag(
                                ValidationTime.CERTIFICATE_ISSUANCE_TIME)).equals(xmlConstraint.getName().getValue())) {
                            wsaCheckAtIssuanceTimePresent = true;
                        } else if (i18nProvider.getMessage(MessageTag.QWAC_IS_WSA_AT_TIME, ValidationProcessUtils.getValidationTimeMessageTag(
                                ValidationTime.VALIDATION_TIME)).equals(xmlConstraint.getName().getValue())) {
                            wsaCheckAtValidationTimePresent = true;
                        }
                    } else if (MessageTag.QWAC_VAL_PERIOD.getId().equals(xmlConstraint.getName().getKey())) {
                        certValidityPeriodCheckPresent = true;
                    } else if (MessageTag.QWAC_DOMAIN_NAME.getId().equals(xmlConstraint.getName().getKey())) {
                        domainNamePresent = true;
                    } else if (MessageTag.QWAC2_EXT_KEY_USAGE.getId().equals(xmlConstraint.getName().getKey())) {
                        extKeyUsageCheckPresent = true;
                    } else if (MessageTag.BBB_ACCEPT.getId().equals(xmlConstraint.getName().getKey())) {
                        bbbCheckConclusive = true;
                    }
                }

                is2QWACProcessPresent = true;
            }
        }
        assertTrue(certPolicyCheckPresent);
        assertTrue(certQualConclusiveCheckPresent);
        assertTrue(wsaCheckAtIssuanceTimePresent);
        assertTrue(wsaCheckAtValidationTimePresent);
        assertTrue(certValidityPeriodCheckPresent);
        assertTrue(domainNamePresent);
        assertTrue(extKeyUsageCheckPresent);
        assertTrue(bbbCheckConclusive);
        assertTrue(is2QWACProcessPresent);

        checkReports(reports);
    }

    @Test
    void qwac2ValidationInPastTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/qwac-validation/2-qwac-valid-diag-data.xml"));
        assertNotNull(diagnosticData);

        diagnosticData.setValidationDate(DSSUtils.getUtcDate(2020, Calendar.JANUARY, 1));

        String certificateId = "C-83D242F9A51C7A62BA1B774268EAAECBAB097479E83D8675C14F02DFB269FE77";

        QWACCertificateProcessExecutor executor = new QWACCertificateProcessExecutor();
        executor.setCertificateId(certificateId);
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        CertificateReports reports = executor.execute();

        SimpleCertificateReport simpleReport = reports.getSimpleReport();
        assertNotNull(simpleReport);

        assertEquals(CertificateQualification.NA, simpleReport.getQualificationAtCertificateIssuance());
        assertTrue(Utils.isCollectionEmpty(simpleReport.getQualificationInfoAtIssuanceTime(certificateId)));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getQualificationWarningsAtIssuanceTime(certificateId)));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getQualificationErrorsAtIssuanceTime(certificateId)));

        assertEquals(CertificateQualification.NA, simpleReport.getQualificationAtValidationTime());
        assertTrue(Utils.isCollectionEmpty(simpleReport.getQualificationInfoAtValidationTime(certificateId)));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getQualificationWarningsAtValidationTime(certificateId)));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getQualificationErrorsAtValidationTime(certificateId)));

        assertEquals(QWACProfile.NOT_QWAC, simpleReport.getQWACProfile());

        String bindingSignatureIssuerId = simpleReport.getTLSBindingSignatureIssuerCertificate().getId();
        assertEquals(CertificateQualification.QCERT_FOR_WSA, simpleReport.getTLSBindingSignatureIssuerQualificationAtCertificateIssuance());
        assertTrue(Utils.isCollectionEmpty(simpleReport.getQualificationInfoAtIssuanceTime(bindingSignatureIssuerId)));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getQualificationWarningsAtIssuanceTime(bindingSignatureIssuerId)));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getQualificationErrorsAtIssuanceTime(bindingSignatureIssuerId)));

        assertEquals(CertificateQualification.CERT_FOR_WSA, simpleReport.getTLSBindingSignatureIssuerQualificationAtValidationTime());
        assertTrue(Utils.isCollectionEmpty(simpleReport.getQualificationInfoAtValidationTime(bindingSignatureIssuerId)));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getQualificationWarningsAtValidationTime(bindingSignatureIssuerId)));
        assertEquals(1, Utils.collectionSize(simpleReport.getQualificationErrorsAtValidationTime(bindingSignatureIssuerId)));
        assertEquals(QWACProfile.NOT_QWAC, simpleReport.getTLSBindingSignatureIssuerCertificateQWACProfile());

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(QWACProfile.NOT_QWAC, detailedReport.getCertificateQWACProfile(certificateId));

        XmlCertificate xmlCertificate = detailedReport.getXmlCertificateById(certificateId);
        assertNotNull(xmlCertificate);

        XmlQWACProcess qwacProcess = xmlCertificate.getQWACProcess();
        assertNotNull(qwacProcess);
        assertEquals(certificateId, qwacProcess.getId());
        assertEquals(QWACProfile.NOT_QWAC, qwacProcess.getQWACType());
        assertEquals(Indication.FAILED, qwacProcess.getConclusion().getIndication());

        boolean isQWACValidCheckFound = false;
        for (XmlConstraint xmlConstraint : qwacProcess.getConstraint()) {
            if (MessageTag.QWAC_VALID.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                assertEquals(MessageTag.QWAC_VALID_ANS.getId(), xmlConstraint.getError().getKey());
                isQWACValidCheckFound = true;
            }
        }
        assertTrue(isQWACValidCheckFound);

        // 1-qwac checks
        boolean is1QWACProcessPresent = false;
        boolean bbbCheckPresent = false;
        boolean qwac1DomainNamePresent = false;
        boolean linkHeaderPresent = false;
        boolean sigFormCheckPresent = false;
        boolean jadesCheckPresent = false;
        boolean jadesCompactCheckPresent = false;
        boolean expTimeCheckPresent = false;
        boolean sigExpCheckPresent = false;
        boolean qwac2CheckPresent = false;
        boolean sigValidCheckPresent = false;
        boolean tlsCertBindingValidCheckPresent = false;

        boolean isTlsSupportedBy2QWACProcessPresent = false;
        for (XmlValidationQWACProcess xmlValidationQWACProcess : qwacProcess.getValidationQWACProcess()) {
            if (i18nProvider.getMessage(MessageTag.QWAC_VALIDATION_PROFILE,
                    ValidationProcessUtils.getQWACValidationMessageTag(QWACProfile.QWAC_1)).equals(xmlValidationQWACProcess.getTitle())) {
                assertEquals(Indication.FAILED, xmlValidationQWACProcess.getConclusion().getIndication());
                is1QWACProcessPresent = true;

            } else if (i18nProvider.getMessage(MessageTag.QWAC_VALIDATION_PROFILE,
                    ValidationProcessUtils.getQWACValidationMessageTag(QWACProfile.TLS_BY_QWAC_2)).equals(xmlValidationQWACProcess.getTitle())) {
                assertEquals(Indication.INDETERMINATE, xmlValidationQWACProcess.getConclusion().getIndication());
                assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, xmlValidationQWACProcess.getConclusion().getSubIndication());
                for (XmlConstraint xmlConstraint : xmlValidationQWACProcess.getConstraint()) {
                    if (MessageTag.BBB_ACCEPT.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                        assertEquals(MessageTag.BBB_ACCEPT_ANS.getId(), xmlConstraint.getError().getKey());
                        bbbCheckPresent = true;
                    } else if (MessageTag.QWAC_DOMAIN_NAME.getId().equals(xmlConstraint.getName().getKey())) {
                        qwac1DomainNamePresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_URL.getId().equals(xmlConstraint.getName().getKey())) {
                        linkHeaderPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG.getId().equals(xmlConstraint.getName().getKey())) {
                        sigFormCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG_FORM.getId().equals(xmlConstraint.getName().getKey())) {
                        jadesCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG_SER.getId().equals(xmlConstraint.getName().getKey())) {
                        jadesCompactCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG_EXP.getId().equals(xmlConstraint.getName().getKey())) {
                        expTimeCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG_EXPIRY_DATE.getId().equals(xmlConstraint.getName().getKey())) {
                        sigExpCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_QWAC2.getId().equals(xmlConstraint.getName().getKey())) {
                        qwac2CheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG_VALID.getId().equals(xmlConstraint.getName().getKey())) {
                        sigValidCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_CERT_IDENTIFIED.getId().equals(xmlConstraint.getName().getKey())) {
                        tlsCertBindingValidCheckPresent = true;
                    }
                }

                isTlsSupportedBy2QWACProcessPresent = true;
            }
        }
        assertTrue(is1QWACProcessPresent);
        assertTrue(bbbCheckPresent);
        assertFalse(qwac1DomainNamePresent);
        assertFalse(linkHeaderPresent);
        assertFalse(sigFormCheckPresent);
        assertFalse(jadesCheckPresent);
        assertFalse(jadesCompactCheckPresent);
        assertFalse(expTimeCheckPresent);
        assertFalse(sigExpCheckPresent);
        assertFalse(qwac2CheckPresent);
        assertFalse(sigValidCheckPresent);
        assertFalse(tlsCertBindingValidCheckPresent);
        assertTrue(isTlsSupportedBy2QWACProcessPresent);

        XmlSignature tlsCertificateBindingSignature = diagnosticData
                .getConnectionInfo().getTLSCertificateBindingSignature().getSignature();

        XmlBasicBuildingBlocks sigBBB = detailedReport.getBasicBuildingBlockById(tlsCertificateBindingSignature.getId());
        assertNotNull(sigBBB);
        assertEquals(Indication.INDETERMINATE, sigBBB.getConclusion().getIndication());
        assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, sigBBB.getConclusion().getSubIndication());

        XmlSAV xmlSAV = sigBBB.getSAV();
        assertNotNull(xmlSAV);
        assertEquals(Indication.PASSED, xmlSAV.getConclusion().getIndication());

        boolean signCertCheckPresent = false;
        boolean signCertOnlyOneCheckPresent = false;
        boolean kidCheckPresent = false;
        boolean signTimeCheckPresent = false;
        boolean ctyCheckPresent = false;
        for (XmlConstraint xmlConstraint : xmlSAV.getConstraint()) {
            assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
            if (MessageTag.BBB_ICS_ISASCP.getId().equals(xmlConstraint.getName().getKey())) {
                signCertCheckPresent = true;
            } else if (MessageTag.BBB_ICS_ISASCPU.getId().equals(xmlConstraint.getName().getKey())) {
                signCertOnlyOneCheckPresent = true;
            } else if (MessageTag.BBB_ICS_ISAKIDP.getId().equals(xmlConstraint.getName().getKey())) {
                kidCheckPresent = true;
            } else if (MessageTag.BBB_SAV_ISQPSTP.getId().equals(xmlConstraint.getName().getKey())) {
                signTimeCheckPresent = true;
            } else if (MessageTag.BBB_SAV_ISQPCTP.getId().equals(xmlConstraint.getName().getKey())) {
                ctyCheckPresent = true;
            }
        }
        assertTrue(signCertCheckPresent);
        assertTrue(signCertOnlyOneCheckPresent);
        assertTrue(kidCheckPresent);
        assertTrue(signTimeCheckPresent);
        assertTrue(ctyCheckPresent);

        eu.europa.esig.dss.diagnostic.jaxb.XmlCertificate signingCertificate =
                tlsCertificateBindingSignature.getSigningCertificate().getCertificate();
        assertEquals(QWACProfile.NOT_QWAC, detailedReport.getCertificateQWACProfile(signingCertificate.getId()));

        eu.europa.esig.dss.detailedreport.jaxb.XmlSignature xmlSignature = detailedReport.getXmlSignatureById(tlsCertificateBindingSignature.getId());
        assertEquals(Indication.INDETERMINATE, xmlSignature.getConclusion().getIndication());
        assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, xmlSignature.getConclusion().getSubIndication());

        XmlValidationSignatureQualification signatureQualification = xmlSignature.getValidationSignatureQualification();
        assertEquals(SignatureQualification.NOT_ADES, signatureQualification.getSignatureQualification());

        XmlQWACProcess signatureQWACProcess = signatureQualification.getQWACProcess();
        assertEquals(signingCertificate.getId(), signatureQWACProcess.getId());
        assertEquals(QWACProfile.NOT_QWAC, signatureQWACProcess.getQWACType());
        assertEquals(Indication.FAILED, signatureQWACProcess.getConclusion().getIndication());

        // 2-qwac checks
        boolean certPolicyCheckPresent = false;
        boolean certQualConclusiveCheckPresent = false;
        boolean wsaCheckAtIssuanceTimePresent = false;
        boolean wsaCheckAtValidationTimePresent = false;
        boolean certValidityPeriodCheckPresent = false;
        boolean domainNamePresent = false;
        boolean extKeyUsageCheckPresent = false;
        boolean bbbCheckConclusive = false;
        boolean is2QWACProcessPresent = false;
        for (XmlValidationQWACProcess xmlValidationQWACProcess : signatureQWACProcess.getValidationQWACProcess()) {
            if (i18nProvider.getMessage(MessageTag.QWAC_VALIDATION_PROFILE,
                    ValidationProcessUtils.getQWACValidationMessageTag(QWACProfile.QWAC_2)).equals(xmlValidationQWACProcess.getTitle())) {
                assertEquals(Indication.FAILED, xmlValidationQWACProcess.getConclusion().getIndication());
                for (XmlConstraint xmlConstraint : xmlValidationQWACProcess.getConstraint()) {
                    if (MessageTag.QWAC_CERT_POLICY.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        certPolicyCheckPresent = true;
                    } else if (MessageTag.QWAC_CERT_QUAL_CONCLUSIVE.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                        assertEquals(MessageTag.QWAC_CERT_QUAL_CONCLUSIVE_ANS.getId(), xmlConstraint.getError().getKey());
                        certQualConclusiveCheckPresent = true;
                    } else if (MessageTag.QWAC_IS_WSA_AT_TIME.getId().equals(xmlConstraint.getName().getKey())) {
                        if (i18nProvider.getMessage(MessageTag.QWAC_IS_WSA_AT_TIME, ValidationProcessUtils.getValidationTimeMessageTag(
                                ValidationTime.CERTIFICATE_ISSUANCE_TIME)).equals(xmlConstraint.getName().getValue())) {
                            wsaCheckAtIssuanceTimePresent = true;
                        } else if (i18nProvider.getMessage(MessageTag.QWAC_IS_WSA_AT_TIME, ValidationProcessUtils.getValidationTimeMessageTag(
                                ValidationTime.VALIDATION_TIME)).equals(xmlConstraint.getName().getValue())) {
                            wsaCheckAtValidationTimePresent = true;
                        }
                    } else if (MessageTag.QWAC_VAL_PERIOD.getId().equals(xmlConstraint.getName().getKey())) {
                        certValidityPeriodCheckPresent = true;
                    } else if (MessageTag.QWAC_DOMAIN_NAME.getId().equals(xmlConstraint.getName().getKey())) {
                        domainNamePresent = true;
                    } else if (MessageTag.QWAC2_EXT_KEY_USAGE.getId().equals(xmlConstraint.getName().getKey())) {
                        extKeyUsageCheckPresent = true;
                    } else if (MessageTag.BBB_ACCEPT.getId().equals(xmlConstraint.getName().getKey())) {
                        bbbCheckConclusive = true;
                    }
                }

                is2QWACProcessPresent = true;
            }
        }
        assertTrue(certPolicyCheckPresent);
        assertTrue(certQualConclusiveCheckPresent);
        assertFalse(wsaCheckAtIssuanceTimePresent);
        assertFalse(wsaCheckAtValidationTimePresent);
        assertFalse(certValidityPeriodCheckPresent);
        assertFalse(domainNamePresent);
        assertFalse(extKeyUsageCheckPresent);
        assertFalse(bbbCheckConclusive);
        assertTrue(is2QWACProcessPresent);

        checkReports(reports);
    }

    @Test
    void brokenSignatureTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(
                new File("src/test/resources/diag-data/qwac-validation/2-qwac-valid-diag-data.xml"));
        assertNotNull(diagnosticData);

        XmlSignature signature = diagnosticData.getSignatures().get(0);
        signature.getBasicSignature().setSignatureIntact(false);
        signature.getBasicSignature().setSignatureValid(false);

        String certificateId = "C-83D242F9A51C7A62BA1B774268EAAECBAB097479E83D8675C14F02DFB269FE77";

        QWACCertificateProcessExecutor executor = new QWACCertificateProcessExecutor();
        executor.setCertificateId(certificateId);
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(loadDefaultPolicy());
        executor.setCurrentTime(diagnosticData.getValidationDate());

        CertificateReports reports = executor.execute();

        SimpleCertificateReport simpleReport = reports.getSimpleReport();
        assertNotNull(simpleReport);

        assertEquals(CertificateQualification.NA, simpleReport.getQualificationAtCertificateIssuance());
        assertTrue(Utils.isCollectionEmpty(simpleReport.getQualificationInfoAtIssuanceTime(certificateId)));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getQualificationWarningsAtIssuanceTime(certificateId)));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getQualificationErrorsAtIssuanceTime(certificateId)));

        assertEquals(CertificateQualification.NA, simpleReport.getQualificationAtValidationTime());
        assertTrue(Utils.isCollectionEmpty(simpleReport.getQualificationInfoAtValidationTime(certificateId)));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getQualificationWarningsAtValidationTime(certificateId)));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getQualificationErrorsAtValidationTime(certificateId)));

        assertEquals(QWACProfile.NOT_QWAC, simpleReport.getQWACProfile());

        String bindingSignatureIssuerId = simpleReport.getTLSBindingSignatureIssuerCertificate().getId();
        assertEquals(CertificateQualification.QCERT_FOR_WSA, simpleReport.getTLSBindingSignatureIssuerQualificationAtCertificateIssuance());
        assertTrue(Utils.isCollectionEmpty(simpleReport.getQualificationInfoAtIssuanceTime(bindingSignatureIssuerId)));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getQualificationWarningsAtIssuanceTime(bindingSignatureIssuerId)));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getQualificationErrorsAtIssuanceTime(bindingSignatureIssuerId)));

        assertEquals(CertificateQualification.QCERT_FOR_WSA, simpleReport.getTLSBindingSignatureIssuerQualificationAtValidationTime());
        assertTrue(Utils.isCollectionEmpty(simpleReport.getQualificationInfoAtValidationTime(bindingSignatureIssuerId)));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getQualificationWarningsAtValidationTime(bindingSignatureIssuerId)));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getQualificationErrorsAtValidationTime(bindingSignatureIssuerId)));
        assertEquals(QWACProfile.QWAC_2, simpleReport.getTLSBindingSignatureIssuerCertificateQWACProfile());

        DetailedReport detailedReport = reports.getDetailedReport();
        assertEquals(QWACProfile.NOT_QWAC, detailedReport.getCertificateQWACProfile(certificateId));

        XmlCertificate xmlCertificate = detailedReport.getXmlCertificateById(certificateId);
        assertNotNull(xmlCertificate);

        XmlQWACProcess qwacProcess = xmlCertificate.getQWACProcess();
        assertNotNull(qwacProcess);
        assertEquals(certificateId, qwacProcess.getId());
        assertEquals(QWACProfile.NOT_QWAC, qwacProcess.getQWACType());
        assertEquals(Indication.FAILED, qwacProcess.getConclusion().getIndication());

        boolean isQWACValidCheckFound = false;
        for (XmlConstraint xmlConstraint : qwacProcess.getConstraint()) {
            if (MessageTag.QWAC_VALID.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                isQWACValidCheckFound = true;
            }
        }
        assertTrue(isQWACValidCheckFound);

        // 1-qwac checks
        boolean is1QWACProcessPresent = false;
        boolean bbbCheckPresent = false;
        boolean qwac1DomainNamePresent = false;
        boolean linkHeaderPresent = false;
        boolean sigFormCheckPresent = false;
        boolean jadesCheckPresent = false;
        boolean jadesCompactCheckPresent = false;
        boolean expTimeCheckPresent = false;
        boolean sigExpCheckPresent = false;
        boolean qwac2CheckPresent = false;
        boolean sigValidCheckPresent = false;
        boolean tlsCertBindingValidCheckPresent = false;

        boolean isTlsSupportedBy2QWACProcessPresent = false;
        for (XmlValidationQWACProcess xmlValidationQWACProcess : qwacProcess.getValidationQWACProcess()) {
            if (i18nProvider.getMessage(MessageTag.QWAC_VALIDATION_PROFILE,
                    ValidationProcessUtils.getQWACValidationMessageTag(QWACProfile.QWAC_1)).equals(xmlValidationQWACProcess.getTitle())) {
                assertEquals(Indication.FAILED, xmlValidationQWACProcess.getConclusion().getIndication());
                is1QWACProcessPresent = true;

            } else if (i18nProvider.getMessage(MessageTag.QWAC_VALIDATION_PROFILE,
                    ValidationProcessUtils.getQWACValidationMessageTag(QWACProfile.TLS_BY_QWAC_2)).equals(xmlValidationQWACProcess.getTitle())) {
                assertEquals(Indication.FAILED, xmlValidationQWACProcess.getConclusion().getIndication());
                for (XmlConstraint xmlConstraint : xmlValidationQWACProcess.getConstraint()) {
                    if (MessageTag.BBB_ACCEPT.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        bbbCheckPresent = true;
                    } else if (MessageTag.QWAC_DOMAIN_NAME.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        qwac1DomainNamePresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_URL.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        linkHeaderPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        sigFormCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG_FORM.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        jadesCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG_SER.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        jadesCompactCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG_EXP.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        expTimeCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG_EXPIRY_DATE.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        sigExpCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_QWAC2.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                        qwac2CheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_SIG_VALID.getId().equals(xmlConstraint.getName().getKey())) {
                        assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                        sigValidCheckPresent = true;
                    } else if (MessageTag.TLS_CERT_BINDING_CERT_IDENTIFIED.getId().equals(xmlConstraint.getName().getKey())) {
                        tlsCertBindingValidCheckPresent = true;
                    }
                }

                isTlsSupportedBy2QWACProcessPresent = true;
            }
        }
        assertTrue(is1QWACProcessPresent);
        assertTrue(bbbCheckPresent);
        assertTrue(qwac1DomainNamePresent);
        assertTrue(linkHeaderPresent);
        assertTrue(sigFormCheckPresent);
        assertTrue(jadesCheckPresent);
        assertTrue(jadesCompactCheckPresent);
        assertTrue(expTimeCheckPresent);
        assertTrue(sigExpCheckPresent);
        assertTrue(qwac2CheckPresent);
        assertTrue(sigValidCheckPresent);
        assertFalse(tlsCertBindingValidCheckPresent);
        assertTrue(isTlsSupportedBy2QWACProcessPresent);

        XmlSignature tlsCertificateBindingSignature = diagnosticData
                .getConnectionInfo().getTLSCertificateBindingSignature().getSignature();

        XmlBasicBuildingBlocks sigBBB = detailedReport.getBasicBuildingBlockById(tlsCertificateBindingSignature.getId());
        assertNotNull(sigBBB);
        assertEquals(Indication.FAILED, sigBBB.getConclusion().getIndication());
        assertEquals(SubIndication.SIG_CRYPTO_FAILURE, sigBBB.getConclusion().getSubIndication());

        XmlCV xmlCV = sigBBB.getCV();
        assertNotNull(xmlCV);
        assertEquals(Indication.FAILED, xmlCV.getConclusion().getIndication());
        assertEquals(SubIndication.SIG_CRYPTO_FAILURE, xmlCV.getConclusion().getSubIndication());

        boolean sigIntactCheckFound = false;
        for (XmlConstraint xmlConstraint : xmlCV.getConstraint()) {
            if (MessageTag.BBB_CV_ISI.getId().equals(xmlConstraint.getName().getKey())) {
                assertEquals(XmlStatus.NOT_OK, xmlConstraint.getStatus());
                sigIntactCheckFound = true;
            }
        }
        assertTrue(sigIntactCheckFound);

        eu.europa.esig.dss.diagnostic.jaxb.XmlCertificate signingCertificate =
                tlsCertificateBindingSignature.getSigningCertificate().getCertificate();
        assertEquals(QWACProfile.QWAC_2, detailedReport.getCertificateQWACProfile(signingCertificate.getId()));

        eu.europa.esig.dss.detailedreport.jaxb.XmlSignature xmlSignature = detailedReport.getXmlSignatureById(tlsCertificateBindingSignature.getId());
        assertEquals(Indication.TOTAL_FAILED, xmlSignature.getConclusion().getIndication());
        assertEquals(SubIndication.SIG_CRYPTO_FAILURE, xmlSignature.getConclusion().getSubIndication());

        XmlValidationSignatureQualification signatureQualification = xmlSignature.getValidationSignatureQualification();
        assertEquals(SignatureQualification.NOT_ADES, signatureQualification.getSignatureQualification());

        XmlQWACProcess signatureQWACProcess = signatureQualification.getQWACProcess();
        assertEquals(signingCertificate.getId(), signatureQWACProcess.getId());
        assertEquals(QWACProfile.QWAC_2, signatureQWACProcess.getQWACType());
        assertEquals(Indication.PASSED, signatureQWACProcess.getConclusion().getIndication());

        // 2-qwac checks
        boolean certPolicyCheckPresent = false;
        boolean certQualConclusiveCheckPresent = false;
        boolean wsaCheckAtIssuanceTimePresent = false;
        boolean wsaCheckAtValidationTimePresent = false;
        boolean certValidityPeriodCheckPresent = false;
        boolean domainNamePresent = false;
        boolean extKeyUsageCheckPresent = false;
        boolean bbbCheckConclusive = false;
        boolean is2QWACProcessPresent = false;
        for (XmlValidationQWACProcess xmlValidationQWACProcess : signatureQWACProcess.getValidationQWACProcess()) {
            if (i18nProvider.getMessage(MessageTag.QWAC_VALIDATION_PROFILE,
                    ValidationProcessUtils.getQWACValidationMessageTag(QWACProfile.QWAC_2)).equals(xmlValidationQWACProcess.getTitle())) {
                assertEquals(Indication.PASSED, xmlValidationQWACProcess.getConclusion().getIndication());
                for (XmlConstraint xmlConstraint : xmlValidationQWACProcess.getConstraint()) {
                    assertEquals(XmlStatus.OK, xmlConstraint.getStatus());
                    if (MessageTag.QWAC_CERT_POLICY.getId().equals(xmlConstraint.getName().getKey())) {
                        certPolicyCheckPresent = true;
                    } else if (MessageTag.QWAC_CERT_QUAL_CONCLUSIVE.getId().equals(xmlConstraint.getName().getKey())) {
                        certQualConclusiveCheckPresent = true;
                    } else if (MessageTag.QWAC_IS_WSA_AT_TIME.getId().equals(xmlConstraint.getName().getKey())) {
                        if (i18nProvider.getMessage(MessageTag.QWAC_IS_WSA_AT_TIME, ValidationProcessUtils.getValidationTimeMessageTag(
                                ValidationTime.CERTIFICATE_ISSUANCE_TIME)).equals(xmlConstraint.getName().getValue())) {
                            wsaCheckAtIssuanceTimePresent = true;
                        } else if (i18nProvider.getMessage(MessageTag.QWAC_IS_WSA_AT_TIME, ValidationProcessUtils.getValidationTimeMessageTag(
                                ValidationTime.VALIDATION_TIME)).equals(xmlConstraint.getName().getValue())) {
                            wsaCheckAtValidationTimePresent = true;
                        }
                    } else if (MessageTag.QWAC_VAL_PERIOD.getId().equals(xmlConstraint.getName().getKey())) {
                        certValidityPeriodCheckPresent = true;
                    } else if (MessageTag.QWAC_DOMAIN_NAME.getId().equals(xmlConstraint.getName().getKey())) {
                        domainNamePresent = true;
                    } else if (MessageTag.QWAC2_EXT_KEY_USAGE.getId().equals(xmlConstraint.getName().getKey())) {
                        extKeyUsageCheckPresent = true;
                    } else if (MessageTag.BBB_ACCEPT.getId().equals(xmlConstraint.getName().getKey())) {
                        bbbCheckConclusive = true;
                    }
                }

                is2QWACProcessPresent = true;
            }
        }
        assertTrue(certPolicyCheckPresent);
        assertTrue(certQualConclusiveCheckPresent);
        assertTrue(wsaCheckAtIssuanceTimePresent);
        assertTrue(wsaCheckAtValidationTimePresent);
        assertTrue(certValidityPeriodCheckPresent);
        assertTrue(domainNamePresent);
        assertTrue(extKeyUsageCheckPresent);
        assertTrue(bbbCheckConclusive);
        assertTrue(is2QWACProcessPresent);

        checkReports(reports);
    }

    private void checkReports(CertificateReports reports) {
        assertNotNull(reports);
        assertNotNull(reports.getDiagnosticData());
        assertNotNull(reports.getDiagnosticDataJaxb());
        assertNotNull(reports.getDetailedReport());
        assertNotNull(reports.getDetailedReportJaxb());
        assertNotNull(reports.getSimpleReport());
        assertNotNull(reports.getSimpleReportJaxb());

        unmarshallXmlReports(reports);
    }

    private void unmarshallXmlReports(CertificateReports reports) {

        unmarshallDiagnosticData(reports);
        unmarshallDetailedReport(reports);
        unmarshallSimpleReport(reports);

        mapDiagnosticData(reports);
        mapDetailedReport(reports);
        mapSimpleReport(reports);

    }

    private void unmarshallDiagnosticData(CertificateReports reports) {
        try {
            String xmlDiagnosticData = reports.getXmlDiagnosticData();
            assertTrue(Utils.isStringNotBlank(xmlDiagnosticData));
            assertNotNull(DiagnosticDataFacade.newFacade().unmarshall(xmlDiagnosticData));
        } catch (Exception e) {
            fail(e.getMessage());
        }
    }

    private void mapDiagnosticData(CertificateReports reports) {
        ObjectMapper om = getObjectMapper();

        try {
            String json = om.writeValueAsString(reports.getDiagnosticDataJaxb());
            assertNotNull(json);
            XmlDiagnosticData diagnosticDataObject = om.readValue(json, XmlDiagnosticData.class);
            assertNotNull(diagnosticDataObject);
        } catch (Exception e) {
            fail(e.getMessage());
        }
    }

    private void unmarshallDetailedReport(CertificateReports reports) {
        try {
            String xmlDetailedReport = reports.getXmlDetailedReport();
            assertTrue(Utils.isStringNotBlank(xmlDetailedReport));
            assertNotNull(DetailedReportFacade.newFacade().unmarshall(xmlDetailedReport));
        } catch (Exception e) {
            fail(e.getMessage());
        }
    }

    private void mapDetailedReport(CertificateReports reports) {
        ObjectMapper om = getObjectMapper();
        try {
            String json = om.writeValueAsString(reports.getDetailedReportJaxb());
            assertNotNull(json);
            XmlDetailedReport detailedReportObject = om.readValue(json, XmlDetailedReport.class);
            assertNotNull(detailedReportObject);
        } catch (Exception e) {
            fail(e.getMessage());
        }
    }

    private void unmarshallSimpleReport(CertificateReports reports) {
        try {
            String xmlSimpleReport = reports.getXmlSimpleReport();
            assertTrue(Utils.isStringNotBlank(xmlSimpleReport));
            assertNotNull(SimpleCertificateReportFacade.newFacade().unmarshall(xmlSimpleReport));
        } catch (Exception e) {
            fail(e.getMessage());
        }
    }

    private void mapSimpleReport(CertificateReports reports) {
        ObjectMapper om = getObjectMapper();
        try {
            String json = om.writeValueAsString(reports.getSimpleReportJaxb());
            assertNotNull(json);
            XmlSimpleCertificateReport simpleReportObject = om.readValue(json, XmlSimpleCertificateReport.class);
            assertNotNull(simpleReportObject);
        } catch (Exception e) {
            fail(e.getMessage());
        }
    }

    private static ObjectMapper getObjectMapper() {
        ObjectMapper om = new ObjectMapper();
        JakartaXmlBindAnnotationIntrospector jai = new JakartaXmlBindAnnotationIntrospector(TypeFactory.defaultInstance());
        om.setAnnotationIntrospector(jai);
        om.enable(SerializationFeature.INDENT_OUTPUT);
        return om;
    }

    @Override
    protected EtsiValidationPolicy loadDefaultPolicy() throws Exception {
        return (EtsiValidationPolicy) ValidationPolicyLoader.fromValidationPolicy(QWAC_VALIDATION_POLICY_LOCATION).create();
    }

}
