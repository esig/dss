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
package eu.europa.esig.dss.jades.signature.qwac;

import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.QWACProfile;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.enumerations.TSLType;
import eu.europa.esig.dss.jades.signature.JAdESLevelB2QWACTest;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.http.ResponseEnvelope;
import eu.europa.esig.dss.model.identifier.Identifier;
import eu.europa.esig.dss.model.timedependent.TimeDependentValues;
import eu.europa.esig.dss.model.tsl.TLInfo;
import eu.europa.esig.dss.model.tsl.TLParsingInfoRecord;
import eu.europa.esig.dss.model.tsl.TLValidationJobSummary;
import eu.europa.esig.dss.model.tsl.TrustProperties;
import eu.europa.esig.dss.model.tsl.TrustService;
import eu.europa.esig.dss.model.tsl.TrustServiceProvider;
import eu.europa.esig.dss.model.tsl.TrustServiceStatusAndInformationExtensions;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.simplecertificatereport.SimpleCertificateReport;
import eu.europa.esig.dss.simplecertificatereport.jaxb.XmlSignature;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.client.http.AdvancedDataLoader;
import eu.europa.esig.dss.spi.client.http.AdvancedMemoryDataLoader;
import eu.europa.esig.dss.spi.tsl.TrustedListsCertificateSource;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.qwac.QWACValidator;
import eu.europa.esig.dss.validation.reports.CertificateReports;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.cert.Certificate;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public abstract class AbstractQWACValidationTest extends JAdESLevelB2QWACTest {

    protected DSSDocument tlsCertificateDocument;

    protected DSSDocument documentToSign;

    @BeforeEach
    void init() throws Exception {
        tlsCertificateDocument = new InMemoryDocument(getTLSCertificate().getEncoded(), "TLSCertificate");
        documentToSign = tlsCertificateDocument;
    }

    @Test
    public void validateQWAC() {
        QWACValidator qwacValidator = QWACValidator.fromUrl(getRequestUrl());
        qwacValidator.setCertificateVerifier(getCompleteCertificateVerifier());
        qwacValidator.setDataLoader(getDataLoader());

        CertificateReports certificateReports = qwacValidator.validate();
        assertNotNull(certificateReports);
        // certificateReports.print();

        SimpleCertificateReport simpleReport = certificateReports.getSimpleReport();
        assertEquals(getExpectedQWACProfile(), simpleReport.getQWACProfile());

        XmlSignature tlsBindingSignature = simpleReport.getTLSBindingSignature();
        if (tlsBindingSignaturePresent()) {
            assertNotNull(tlsBindingSignature);
            assertEquals(getExpectedTLSBindingSignatureIndication(), simpleReport.getTLSBindingSignatureIndication());
            assertEquals(getExpectedTLSBindingSignatureSubIndication(), simpleReport.getTLSBindingSignatureSubIndication());
            assertEquals(getExpectedSignatureBindingCertificateQWACProfile(), simpleReport.getTLSBindingSignatureIssuerCertificateQWACProfile());
        } else {
            assertNull(tlsBindingSignature);
        }
    }

    @Override
    public void signAndVerify() {
        // skip
    }

    @Override
    protected DSSDocument getDocumentToSign() {
        return documentToSign;
    }

    @Override
    protected CertificateVerifier getCompleteCertificateVerifier() {
        CertificateVerifier certificateVerifier = super.getCompleteCertificateVerifier();
        certificateVerifier.addTrustedCertSources(getTrustedListsCertificateSource());
        return certificateVerifier;
    }

    protected AdvancedDataLoader getDataLoader() {
        final Map<String, ResponseEnvelope> dataMap = new HashMap<>();
        dataMap.put(getRequestUrl(), toResponseEnvelope(null, getHeaders(), getTLSCertificates()));
        dataMap.put(getTLSBindingSignatureUrl(), toResponseEnvelope(getSignatureBytes(), null, null));
        return new AdvancedMemoryDataLoader(dataMap);
    }

    protected String getRequestUrl() {
        return "https://nowina.lu";
    }

    protected Map<String, List<String>> getHeaders() {
        Map<String, List<String>> headers = new HashMap<>();
        String linkHeaderValue = getLinkHeaderValue();
        if (linkHeaderValue != null) {
            headers.put("Link", Collections.singletonList(linkHeaderValue));
        }
        return headers;
    }

    protected String getLinkHeaderValue() {
        return String.format("<%s>; rel=\"tls-certificate-binding\"", getTLSBindingSignatureUrl());
    }

    protected String getTLSBindingSignatureUrl() {
        return "https://nowina.lu/tls-binding-signature";
    }

    protected List<CertificateToken> getTLSCertificates() {
        return Collections.singletonList(getTLSCertificate());
    }

    protected CertificateToken getTLSCertificate() {
        return getCertificate("TLS Certificate");
    }

    protected TrustedListsCertificateSource getTrustedListsCertificateSource() {
        TrustedListsCertificateSource trustedListsCertificateSource = new TrustedListsCertificateSource();

        Map<CertificateToken, List<TrustProperties>> mapOfTrustProperties = new HashMap<>();
        CertificateToken sdiCertificate = getSDICertificate();
        TrustProperties trustProperties = createTrustProperties(sdiCertificate);
        mapOfTrustProperties.put(sdiCertificate, Collections.singletonList(trustProperties));

        trustedListsCertificateSource.setTrustPropertiesByCertificates(mapOfTrustProperties);

        TLValidationJobSummary tlValidationJobSummary = new TLValidationJobSummary(Collections.emptyList(), Collections.singletonList(trustProperties.getTLInfo()));
        trustedListsCertificateSource.setSummary(tlValidationJobSummary);

        return trustedListsCertificateSource;
    }

    protected TrustProperties createTrustProperties(CertificateToken sdiCertificate) {
        TrustServiceProvider trustServiceProvider = new TrustServiceProvider();
        trustServiceProvider.setTerritory("ZZ");
        trustServiceProvider.setNames(new HashMap<String, List<String>>() {{ put("en", Collections.singletonList(sdiCertificate.getSubject().getRFC2253())); }} );
        trustServiceProvider.setRegistrationIdentifiers(Collections.singletonList("VATZZ-00112233"));

        TrustServiceStatusAndInformationExtensions trustServiceStatusAndInformationExtensions =
                new TrustServiceStatusAndInformationExtensions.TrustServiceStatusAndInformationExtensionsBuilder()
                        .setNames(new HashMap<String, List<String>>() {{ put("en", Collections.singletonList("ZZ Service")); }} )
                        .setType("http://uri.etsi.org/TrstSvc/Svctype/CA/QC")
                        .setStatus("http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted")
                        .setStartDate(DSSUtils.parseRFCDate("2022-03-31T10:00:45Z"))
                        .setAdditionalServiceInfoUris(Collections.singletonList("http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/ForWebSiteAuthentication"))
                        .build();
        TimeDependentValues<TrustServiceStatusAndInformationExtensions> timeDependentValues =
                new TimeDependentValues<>(Collections.singletonList(trustServiceStatusAndInformationExtensions));

        TrustService trustService = new TrustService(Collections.singletonList(sdiCertificate), timeDependentValues);
        trustServiceProvider.setServices(Collections.singletonList(trustService));

        Identifier tlIdentifier = mock(Identifier.class);
        when(tlIdentifier.asXmlId()).thenReturn("TL-ID");

        TLParsingInfoRecord parsingInfoRecord = mock(TLParsingInfoRecord.class);
        when(parsingInfoRecord.getTerritory()).thenReturn("ZZ");
        when(parsingInfoRecord.getTSLType()).thenReturn(TSLType.fromUri("http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUgeneric"));
        when(parsingInfoRecord.getSequenceNumber()).thenReturn(1);
        when(parsingInfoRecord.getVersion()).thenReturn(5);

        TLInfo tlInfo = new TLInfo(null, parsingInfoRecord, null, "ZZ.xml");
        return new TrustProperties(tlInfo, trustServiceProvider, timeDependentValues);
    }

    protected CertificateToken getSDICertificate() {
        return getCertificate("Test-Qualified-CA1-from-ZZ");
    }

    protected byte[] getSignatureBytes() {
        DSSDocument signature = sign();
        return DSSUtils.toByteArray(signature);
    }

    protected ResponseEnvelope toResponseEnvelope(byte[] responseBody, Map<String, List<String>> headers, List<CertificateToken> tlsCertificates) {
        ResponseEnvelope responseEnvelope = new ResponseEnvelope();
        responseEnvelope.setResponseBody(responseBody);
        responseEnvelope.setHeaders(headers);
        if (tlsCertificates != null) {
            responseEnvelope.setTLSCertificates(tlsCertificates.stream().map(CertificateToken::getCertificate).toArray(Certificate[]::new));
        }
        return responseEnvelope;
    }

    protected abstract QWACProfile getExpectedQWACProfile();

    protected abstract QWACProfile getExpectedSignatureBindingCertificateQWACProfile();

    protected boolean tlsBindingSignaturePresent() {
        return true;
    }

    protected Indication getExpectedTLSBindingSignatureIndication() {
        return Indication.TOTAL_PASSED;
    }

    protected SubIndication getExpectedTLSBindingSignatureSubIndication() {
        return null;
    }

}
