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
package eu.europa.esig.dss.validation.qwac;

import eu.europa.esig.dss.detailedreport.DetailedReportFacade;
import eu.europa.esig.dss.detailedreport.jaxb.XmlDetailedReport;
import eu.europa.esig.dss.diagnostic.DiagnosticDataFacade;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.enumerations.QWACProfile;
import eu.europa.esig.dss.enumerations.TSLType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
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
import eu.europa.esig.dss.simplecertificatereport.SimpleCertificateReportFacade;
import eu.europa.esig.dss.simplecertificatereport.jaxb.XmlSimpleCertificateReport;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.client.http.AdvancedMemoryDataLoader;
import eu.europa.esig.dss.spi.tsl.TrustedListsCertificateSource;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.ExternalResourcesOCSPSource;
import eu.europa.esig.dss.validation.reports.CertificateReports;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.security.cert.Certificate;
import java.util.Calendar;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class QWACValidatorTest {

    @Test
    void testOnline() throws Exception {
        QWACValidator validator = QWACValidator.fromUrl("https://harica.gr");
        validator.setCertificateVerifier(new CommonCertificateVerifier());

        CertificateReports reports = validator.validate();
        validateReports(reports);

        SimpleCertificateReport simpleReport = reports.getSimpleReport();
        assertEquals(QWACProfile.NOT_QWAC, simpleReport.getQWACProfile());
    }

    @Test
    void test1Qwac() throws Exception {
        CertificateToken haricaCert = DSSUtils.loadCertificate(new File("src/test/resources/qwac/harica.cer"));
        CertificateToken haricaCA = DSSUtils.loadCertificate(new File("src/test/resources/qwac/harica_ca.cer"));
        DSSDocument haricaCertOCSP = new FileDocument("src/test/resources/qwac/harica_ocsp.bin");

        Map<String, ResponseEnvelope> dataMap = new HashMap<>();
        dataMap.put("https://harica.gr", toResponseEnvelope(null, null, Collections.singletonList(haricaCert)));
        AdvancedMemoryDataLoader memoryDataLoader = new AdvancedMemoryDataLoader(dataMap);

        QWACValidator validator = QWACValidator.fromUrl("https://harica.gr");
        validator.setDataLoader(memoryDataLoader);
        validator.setValidationTime(DSSUtils.getUtcDate(2025, Calendar.DECEMBER, 1));

        CommonCertificateVerifier certificateVerifier = new CommonCertificateVerifier();
        TrustedListsCertificateSource trustedListsCertificateSource = new TrustedListsCertificateSource();

        TrustServiceProvider trustServiceProvider = new TrustServiceProvider();
        trustServiceProvider.setTerritory("EL");
        trustServiceProvider.setNames(new HashMap<String, List<String>>() {{ put("EN", Collections.singletonList(haricaCA.getSubject().getRFC2253())); }} );
        trustServiceProvider.setRegistrationIdentifiers(Collections.singletonList("VATEL-099028220"));

        TrustServiceStatusAndInformationExtensions trustServiceStatusAndInformationExtensions =
                new TrustServiceStatusAndInformationExtensions.TrustServiceStatusAndInformationExtensionsBuilder()
                        .setNames(new HashMap<String, List<String>>() {{ put("EN", Collections.singletonList("EL Service")); }} )
                        .setType("http://uri.etsi.org/TrstSvc/Svctype/CA/QC")
                        .setStatus("http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted")
                        .setStartDate(DSSUtils.parseRFCDate("2022-03-31T10:00:45Z"))
                        .setAdditionalServiceInfoUris(Collections.singletonList("http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/ForWebSiteAuthentication"))
                        .build();
        TimeDependentValues<TrustServiceStatusAndInformationExtensions> timeDependentValues =
                new TimeDependentValues<>(Collections.singletonList(trustServiceStatusAndInformationExtensions));

        TrustService trustService = new TrustService(Collections.singletonList(haricaCA), timeDependentValues);
        trustServiceProvider.setServices(Collections.singletonList(trustService));

        Identifier tlIdentifier = mock(Identifier.class);
        when(tlIdentifier.asXmlId()).thenReturn("TL-ID");

        TLInfo tlInfo = mock(TLInfo.class);
        when(tlInfo.getUrl()).thenReturn("https://www.eett.gr/tsl/EL-TSL.xml");
        when(tlInfo.getDSSId()).thenReturn(tlIdentifier);
        when(tlInfo.getDSSIdAsString()).thenReturn("TL-ID");

        TLParsingInfoRecord parsingInfoRecord = mock(TLParsingInfoRecord.class);
        when(parsingInfoRecord.getTerritory()).thenReturn("EL");
        when(parsingInfoRecord.getTSLType()).thenReturn(TSLType.fromUri("http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUgeneric"));
        when(parsingInfoRecord.getSequenceNumber()).thenReturn(1);
        when(parsingInfoRecord.getVersion()).thenReturn(5);

        when(tlInfo.getParsingCacheInfo()).thenReturn(parsingInfoRecord);

        TrustProperties trustProperties = new TrustProperties(tlInfo, trustServiceProvider, timeDependentValues);

        Map<CertificateToken, List<TrustProperties>> mapOfTrustProperties = new HashMap<>();
        mapOfTrustProperties.put(haricaCA, Collections.singletonList(trustProperties));

        trustedListsCertificateSource.setTrustPropertiesByCertificates(mapOfTrustProperties);

        TLValidationJobSummary tlValidationJobSummary = new TLValidationJobSummary(Collections.emptyList(), Collections.singletonList(tlInfo));
        trustedListsCertificateSource.setSummary(tlValidationJobSummary);

        certificateVerifier.addTrustedCertSources(trustedListsCertificateSource);

        ExternalResourcesOCSPSource ocspSource = new ExternalResourcesOCSPSource(haricaCertOCSP);
        certificateVerifier.setOcspSource(ocspSource);

        validator.setCertificateVerifier(certificateVerifier);

        CertificateReports reports = validator.validate();
        validateReports(reports);

        SimpleCertificateReport simpleReport = reports.getSimpleReport();
        assertEquals(QWACProfile.QWAC_1, simpleReport.getQWACProfile());
    }

    private void validateReports(CertificateReports reports) throws Exception {
        assertNotNull(reports);
        assertNotNull(reports.getDiagnosticDataJaxb());
        assertNotNull(reports.getXmlDiagnosticData());
        assertNotNull(reports.getDetailedReportJaxb());
        assertNotNull(reports.getXmlDetailedReport());
        assertNotNull(reports.getSimpleReportJaxb());
        assertNotNull(reports.getXmlSimpleReport());

        DiagnosticDataFacade diagnosticDataFacade = DiagnosticDataFacade.newFacade();
        String marshalled = diagnosticDataFacade.marshall(reports.getDiagnosticDataJaxb(), true);
        assertNotNull(marshalled);
        XmlDiagnosticData unmarshalled = diagnosticDataFacade.unmarshall(marshalled);
        assertNotNull(unmarshalled);

        SimpleCertificateReportFacade simpleCertificateReportFacade = SimpleCertificateReportFacade.newFacade();
        String marshalledSimpleReport = simpleCertificateReportFacade.marshall(reports.getSimpleReportJaxb(), true);
        assertNotNull(marshalledSimpleReport);
        XmlSimpleCertificateReport unmarshalledSimpleReport = simpleCertificateReportFacade.unmarshall(marshalledSimpleReport);
        assertNotNull(unmarshalledSimpleReport);
        assertNotNull(simpleCertificateReportFacade.generateHtmlReport(marshalledSimpleReport));
        assertNotNull(simpleCertificateReportFacade.generateHtmlReport(reports.getSimpleReportJaxb()));

        DetailedReportFacade detailedReportFacade = DetailedReportFacade.newFacade();
        String marshalledDetailedReport = detailedReportFacade.marshall(reports.getDetailedReportJaxb(), true);
        assertNotNull(marshalledDetailedReport);
        XmlDetailedReport unmarshalledDetailedReport = detailedReportFacade.unmarshall(marshalledDetailedReport);
        assertNotNull(unmarshalledDetailedReport);
        assertNotNull(detailedReportFacade.generateHtmlReport(marshalledDetailedReport));
        assertNotNull(detailedReportFacade.generateHtmlReport(reports.getDetailedReportJaxb()));
    }

    private ResponseEnvelope toResponseEnvelope(byte[] responseBody, Map<String, List<String>> headers, List<CertificateToken> tlsCertificates) {
        ResponseEnvelope responseEnvelope = new ResponseEnvelope();
        responseEnvelope.setResponseBody(responseBody);
        responseEnvelope.setHeaders(headers);
        if (tlsCertificates != null) {
            responseEnvelope.setTLSCertificates(tlsCertificates.stream().map(CertificateToken::getCertificate).toArray(Certificate[]::new));
        }
        return responseEnvelope;
    }

}
