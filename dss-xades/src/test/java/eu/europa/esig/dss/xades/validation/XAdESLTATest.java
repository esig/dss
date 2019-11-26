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
package eu.europa.esig.dss.xades.validation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.xml.bind.JAXBException;

import org.junit.jupiter.api.Test;
import org.xml.sax.SAXException;

import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTrustedList;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTrustedService;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTrustedServiceProvider;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.tsl.TLInfo;
import eu.europa.esig.dss.spi.tsl.TLValidationJobSummary;
import eu.europa.esig.dss.spi.tsl.TrustProperties;
import eu.europa.esig.dss.spi.tsl.TrustServiceStatusAndInformationExtensions;
import eu.europa.esig.dss.spi.tsl.TrustedListsCertificateSource;
import eu.europa.esig.dss.spi.tsl.TrustServiceStatusAndInformationExtensions.TrustServiceStatusAndInformationExtensionsBuilder;
import eu.europa.esig.dss.spi.tsl.builder.TrustServiceProviderBuilder;
import eu.europa.esig.dss.spi.util.MutableTimeDependentValues;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.test.signature.UnmarshallingTester;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;

public class XAdESLTATest {

	@Test
	public void test() {
		DSSDocument doc = new FileDocument("src/test/resources/validation/XAdESLTA.xml");
		SignedDocumentValidator sdv = SignedDocumentValidator.fromDocument(doc);
		CommonCertificateVerifier certificateVerifier = new CommonCertificateVerifier();
		CommonTrustedCertificateSource trustedCertSource = new CommonTrustedCertificateSource();
		trustedCertSource.addCertificate(DSSUtils.loadCertificateFromBase64EncodedString(
				"MIIDjjCCAnagAwIBAgIIKv++n6Lw6YcwDQYJKoZIhvcNAQEFBQAwKDELMAkGA1UEBhMCQkUxGTAXBgNVBAMTEEJlbGdpdW0gUm9vdCBDQTIwHhcNMDcxMDA0MTAwMDAwWhcNMjExMjE1MDgwMDAwWjAoMQswCQYDVQQGEwJCRTEZMBcGA1UEAxMQQmVsZ2l1bSBSb290IENBMjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMZzQh6S/3UPi790hqc/7bIYLS2X+an7mEoj39WN4IzGMhwWLQdC1i22bi+n9fzGhYJdld61IgDMqFNAn68KNaJ6x+HK92AQZw6nUHMXU5WfIp8MXW+2QbyM69odRr2nlL/zGsvU+40OHjPIltfsjFPekx40HopQcSZYtF3CiInaYNKJIT/e1wEYNm7hLHADBGXvmAYrXR5i3FVr/mZkIV/4L+HXmymvb82fqgxG0YjFnaKVn6w/Fa7yYd/vw2uaItgscf1YHewApDgglVrH1Tdjuk+bqv5WRi5j2Qsj1Yr6tSPwiRuhFA0m2kHwOI8w7QUmecFLTqG4flVSOmlGhHUCAwEAAaOBuzCBuDAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zBCBgNVHSAEOzA5MDcGBWA4CQEBMC4wLAYIKwYBBQUHAgEWIGh0dHA6Ly9yZXBvc2l0b3J5LmVpZC5iZWxnaXVtLmJlMB0GA1UdDgQWBBSFiuv0xbu+DlkDlN7WgAEV4xCcOTARBglghkgBhvhCAQEEBAMCAAcwHwYDVR0jBBgwFoAUhYrr9MW7vg5ZA5Te1oABFeMQnDkwDQYJKoZIhvcNAQEFBQADggEBAFHYhd27V2/MoGy1oyCcUwnzSgEMdL8rs5qauhjyC4isHLMzr87lEwEnkoRYmhC598wUkmt0FoqW6FHvv/pKJaeJtmMrXZRY0c8RcrYeuTlBFk0pvDVTC9rejg7NqZV3JcqUWumyaa7YwBO+mPyWnIR/VRPmPIfjvCCkpDZoa01gZhz5v6yAlGYuuUGK02XThIAC71AdXkbc98m6tTR8KvPG2F9fVJ3bTc0R5/0UAoNmXsimABKgX77OFP67H6dh96tK8QYUn8pJQsKpvO2FsauBQeYNxUJpU4c5nUwfAA4+Bw11V0SoU7Q2dmSZ3G7rPUZuFF1eR1ONeE3gJ7uOhXY="));
		certificateVerifier.setTrustedCertSource(trustedCertSource);
		sdv.setCertificateVerifier(certificateVerifier);
		Reports reports = sdv.validateDocument();
		assertNotNull(reports);
		UnmarshallingTester.unmarshallXmlReports(reports);
	}

	@Test
	@SuppressWarnings("serial")
	public void testWithTrustedService() throws JAXBException, IOException, SAXException {
		DSSDocument doc = new FileDocument("src/test/resources/validation/XAdESLTA.xml");
		SignedDocumentValidator sdv = SignedDocumentValidator.fromDocument(doc);
		CommonCertificateVerifier certificateVerifier = new CommonCertificateVerifier();
		TrustedListsCertificateSource trustedCertSource = new TrustedListsCertificateSource();
		
		TrustServiceProviderBuilder trustServiceProviderBuilder = new TrustServiceProviderBuilder();
		trustServiceProviderBuilder.setTerritory("BE");
		trustServiceProviderBuilder.setNames(new HashMap<String, List<String>>() {{ put("EN", Arrays.asList("CN=Belgium Root CA2, C=BE")); }} );
		trustServiceProviderBuilder.setRegistrationIdentifiers(Arrays.asList("VATDE-203462028"));
		
		TrustServiceStatusAndInformationExtensionsBuilder extensionsBuilder = new TrustServiceStatusAndInformationExtensions.
				TrustServiceStatusAndInformationExtensionsBuilder();
		extensionsBuilder.setNames(new HashMap<String, List<String>>() {{ put("EN", Arrays.asList("CN=Belgium Root CA2, C=BE")); }} );
		extensionsBuilder.setType("http://uri.etsi.org/TrstSvc/Svctype/CA/QC");
		extensionsBuilder.setStatus("http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted");
		extensionsBuilder.setConditionsForQualifiers(Collections.emptyList());
		extensionsBuilder.setAdditionalServiceInfoUris(Collections.emptyList());
		extensionsBuilder.setServiceSupplyPoints(Collections.emptyList());
		extensionsBuilder.setExpiredCertsRevocationInfo(null);
		extensionsBuilder.setStartDate(new Date());
		extensionsBuilder.setEndDate(new Date());
		TrustServiceStatusAndInformationExtensions statusAndInformationExtensions = extensionsBuilder.build();
		
		MutableTimeDependentValues<TrustServiceStatusAndInformationExtensions> statusHistoryList = new MutableTimeDependentValues<TrustServiceStatusAndInformationExtensions>();
		statusHistoryList.addOldest(statusAndInformationExtensions);
		
		TLInfo tlInfo = new TLInfo(null, null, null, "BE.xml");
		TrustProperties trustProperties = new TrustProperties(tlInfo.getIdentifier(), trustServiceProviderBuilder.build(), statusHistoryList);

		Map<CertificateToken, List<TrustProperties>> trustPropertiesByCertMap = new HashMap<CertificateToken, List<TrustProperties>>();
		trustPropertiesByCertMap.put(DSSUtils.loadCertificateFromBase64EncodedString(
				"MIIDjjCCAnagAwIBAgIIKv++n6Lw6YcwDQYJKoZIhvcNAQEFBQAwKDELMAkGA1UEBhMCQkUxGTAXBgNVBAMTEEJlbGdpdW0gUm9vdCBDQTIwHhcNMDcxMDA0MTAwMDAwWhcNMjExMjE1MDgwMDAwWjAoMQswCQYDVQQGEwJCRTEZMBcGA1UEAxMQQmVsZ2l1bSBSb290IENBMjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMZzQh6S/3UPi790hqc/7bIYLS2X+an7mEoj39WN4IzGMhwWLQdC1i22bi+n9fzGhYJdld61IgDMqFNAn68KNaJ6x+HK92AQZw6nUHMXU5WfIp8MXW+2QbyM69odRr2nlL/zGsvU+40OHjPIltfsjFPekx40HopQcSZYtF3CiInaYNKJIT/e1wEYNm7hLHADBGXvmAYrXR5i3FVr/mZkIV/4L+HXmymvb82fqgxG0YjFnaKVn6w/Fa7yYd/vw2uaItgscf1YHewApDgglVrH1Tdjuk+bqv5WRi5j2Qsj1Yr6tSPwiRuhFA0m2kHwOI8w7QUmecFLTqG4flVSOmlGhHUCAwEAAaOBuzCBuDAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zBCBgNVHSAEOzA5MDcGBWA4CQEBMC4wLAYIKwYBBQUHAgEWIGh0dHA6Ly9yZXBvc2l0b3J5LmVpZC5iZWxnaXVtLmJlMB0GA1UdDgQWBBSFiuv0xbu+DlkDlN7WgAEV4xCcOTARBglghkgBhvhCAQEEBAMCAAcwHwYDVR0jBBgwFoAUhYrr9MW7vg5ZA5Te1oABFeMQnDkwDQYJKoZIhvcNAQEFBQADggEBAFHYhd27V2/MoGy1oyCcUwnzSgEMdL8rs5qauhjyC4isHLMzr87lEwEnkoRYmhC598wUkmt0FoqW6FHvv/pKJaeJtmMrXZRY0c8RcrYeuTlBFk0pvDVTC9rejg7NqZV3JcqUWumyaa7YwBO+mPyWnIR/VRPmPIfjvCCkpDZoa01gZhz5v6yAlGYuuUGK02XThIAC71AdXkbc98m6tTR8KvPG2F9fVJ3bTc0R5/0UAoNmXsimABKgX77OFP67H6dh96tK8QYUn8pJQsKpvO2FsauBQeYNxUJpU4c5nUwfAA4+Bw11V0SoU7Q2dmSZ3G7rPUZuFF1eR1ONeE3gJ7uOhXY="),
				Arrays.asList(trustProperties));
		trustedCertSource.setTrustPropertiesByCertificates(trustPropertiesByCertMap);
		
		TLValidationJobSummary summary = new TLValidationJobSummary(Collections.emptyList(), Arrays.asList(tlInfo));
		trustedCertSource.setSummary(summary);
		
		certificateVerifier.setTrustedCertSource(trustedCertSource);
		sdv.setCertificateVerifier(certificateVerifier);
		Reports reports = sdv.validateDocument();
		// reports.print();
		assertNotNull(reports);
		UnmarshallingTester.unmarshallXmlReports(reports);

		String rootCaCertId = "C-9F9744463BE13714754E1A3BECF98C08CC205E4AB32028F4E2830C4A1B2775B8";

		DiagnosticData diagnosticData = reports.getDiagnosticData();
		CertificateWrapper certificateById = diagnosticData.getUsedCertificateById(rootCaCertId);
		assertNotNull(certificateById);
		assertTrue(certificateById.isTrusted());
		List<XmlTrustedServiceProvider> trustServiceProviders = certificateById.getTrustServiceProviders();
		assertNotNull(trustServiceProviders);
		
		XmlTrustedServiceProvider xmlTrustedServiceProvider = trustServiceProviders.get(0);
		assertNull(xmlTrustedServiceProvider.getLOTL());
		XmlTrustedList xmlTL = xmlTrustedServiceProvider.getTL();
		assertNotNull(xmlTL);
		assertNotNull(xmlTL);
		assertNotNull(xmlTL.getId());
		assertNotNull(xmlTL.getUrl());
		
		List<XmlTrustedService> trustedServices = xmlTrustedServiceProvider.getTrustedServices();
		assertNotNull(trustedServices);
		for (XmlTrustedService xmlTrustedService : trustedServices) {
			assertEquals(rootCaCertId, xmlTrustedService.getServiceDigitalIdentifier().getId());
		}
	}

}
