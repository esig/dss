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
package eu.europa.esig.dss.xades.signature;

import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.TrustServiceWrapper;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.timedependent.MutableTimeDependentValues;
import eu.europa.esig.dss.model.tsl.TLInfo;
import eu.europa.esig.dss.model.tsl.TLValidationJobSummary;
import eu.europa.esig.dss.model.tsl.TrustProperties;
import eu.europa.esig.dss.model.tsl.TrustServiceProvider;
import eu.europa.esig.dss.model.tsl.TrustServiceStatusAndInformationExtensions;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.spi.tsl.TrustedListsCertificateSource;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;
import org.junit.jupiter.api.BeforeEach;

import java.io.File;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class XAdESLevelBWithTrustServicesTest extends AbstractXAdESTestSignature {

    private DocumentSignatureService<XAdESSignatureParameters, XAdESTimestampParameters> service;
    private XAdESSignatureParameters signatureParameters;
    private DSSDocument documentToSign;

    @BeforeEach
    void init() throws Exception {
        documentToSign = new FileDocument(new File("src/test/resources/sample.xml"));

        signatureParameters = new XAdESSignatureParameters();
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
        signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
        signatureParameters.bLevel().setTrustAnchorBPPolicy(false);

        service = new XAdESService(getOfflineCertificateVerifier());
    }

    @Override
    protected SignedDocumentValidator getValidator(DSSDocument signedDocument) {
        SignedDocumentValidator validator = super.getValidator(signedDocument);

        CertificateVerifier certificateVerifier = getCompleteCertificateVerifier();
        TrustedListsCertificateSource trustedCertSource = new TrustedListsCertificateSource();

        CertificateToken trustCertificate = getCertificateByPrimaryKey(2003, "cc-root-ca");

        TrustServiceProvider trustServiceProvider = new TrustServiceProvider();
        trustServiceProvider.setTerritory("XX");
        trustServiceProvider.setNames(new HashMap<String, List<String>>() {{ put("EN", Collections.singletonList(trustCertificate.getSubject().getRFC2253())); }} );
        trustServiceProvider.setRegistrationIdentifiers(Collections.singletonList("REG-0123456"));

        TrustServiceStatusAndInformationExtensions.TrustServiceStatusAndInformationExtensionsBuilder extensionsBuilder = new TrustServiceStatusAndInformationExtensions.
                TrustServiceStatusAndInformationExtensionsBuilder();
        extensionsBuilder.setNames(new HashMap<String, List<String>>() {{ put("EN", Collections.singletonList(trustCertificate.getSubject().getRFC2253())); }} );
        extensionsBuilder.setType("http://uri.etsi.org/TrstSvc/Svctype/CA/QC");
        extensionsBuilder.setStatus("http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted");
        extensionsBuilder.setConditionsForQualifiers(Collections.emptyList());
        extensionsBuilder.setAdditionalServiceInfoUris(Collections.emptyList());
        extensionsBuilder.setServiceSupplyPoints(Collections.emptyList());
        extensionsBuilder.setExpiredCertsRevocationInfo(null);
        extensionsBuilder.setStartDate(trustCertificate.getNotBefore());
        extensionsBuilder.setEndDate(trustCertificate.getNotAfter());
        TrustServiceStatusAndInformationExtensions statusAndInformationExtensions = extensionsBuilder.build();

        MutableTimeDependentValues<TrustServiceStatusAndInformationExtensions> statusHistoryList = new MutableTimeDependentValues<>();
        statusHistoryList.addOldest(statusAndInformationExtensions);

        TLInfo tlInfo = new TLInfo(null, null, null, "XX.xml");
        TrustProperties trustProperties = new TrustProperties(tlInfo, trustServiceProvider, statusHistoryList);

        Map<CertificateToken, List<TrustProperties>> trustPropertiesByCertMap = new HashMap<>();
        trustPropertiesByCertMap.put(trustCertificate, Collections.singletonList(trustProperties));
        trustedCertSource.setTrustPropertiesByCertificates(trustPropertiesByCertMap);

        TLValidationJobSummary summary = new TLValidationJobSummary(Collections.emptyList(), Collections.singletonList(tlInfo));
        trustedCertSource.setSummary(summary);

        certificateVerifier.setTrustedCertSources(trustedCertSource);
        validator.setCertificateVerifier(certificateVerifier);

        return validator;
    }

    @Override
    protected void checkSigningCertificateValue(DiagnosticData diagnosticData) {
        super.checkSigningCertificateValue(diagnosticData);

        String signingCertificateId = diagnosticData.getSigningCertificateId(diagnosticData.getFirstSignatureId());
        CertificateWrapper signingCertificate = diagnosticData.getCertificateById(signingCertificateId);

        assertEquals(1, signingCertificate.getTrustServiceProviders().size());
        assertEquals(1, signingCertificate.getTrustServices().size());

        TrustServiceWrapper trustServiceWrapper = signingCertificate.getTrustServices().get(0);
        assertEquals("http://uri.etsi.org/TrstSvc/Svctype/CA/QC", trustServiceWrapper.getType());
        assertEquals("http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted", trustServiceWrapper.getStatus());
    }

    @Override
    protected void checkCertificateChain(DiagnosticData diagnosticData) {
        super.checkCertificateChain(diagnosticData);

        boolean trustAnchorFound = false;
        for (String certId : diagnosticData.getSignatureCertificateChainIds(diagnosticData.getFirstSignatureId())) {
            CertificateWrapper certificate = diagnosticData.getCertificateById(certId);
            if (certificate.isTrusted()) {
                assertEquals("2002", certificate.getSerialNumber());
                assertEquals("cc-root-ca", certificate.getCommonName());
                assertEquals("C=LU,OU=PKI-TEST,O=Nowina Solutions,CN=external-ca", certificate.getCertificateIssuerDN());

                assertEquals(1, certificate.getTrustServiceProviders().size());
                assertEquals(1, certificate.getTrustServices().size());

                trustAnchorFound = true;
                break;
            }
        }
        assertTrue(trustAnchorFound);
    }

    @Override
    protected void verifySimpleReport(SimpleReport simpleReport) {
        super.verifySimpleReport(simpleReport);

        assertFalse(simpleReport.getQualificationErrors(simpleReport.getFirstSignatureId()).stream()
                .anyMatch(m -> MessageTag.QUAL_CERT_TRUSTED_LIST_REACHED_ANS.getId().equals(m.getKey())));
    }

    @Override
    protected DocumentSignatureService<XAdESSignatureParameters, XAdESTimestampParameters> getService() {
        return service;
    }

    @Override
    protected XAdESSignatureParameters getSignatureParameters() {
        return signatureParameters;
    }

    @Override
    protected DSSDocument getDocumentToSign() {
        return documentToSign;
    }

    @Override
    protected String getSigningAlias() {
        return GOOD_USER_CROSS_CERTIF;
    }

}
