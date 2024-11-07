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
package eu.europa.esig.dss.tsl.job;

import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.service.http.commons.FileCacheDataLoader;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.client.http.DSSFileLoader;
import eu.europa.esig.dss.model.tsl.TrustProperties;
import eu.europa.esig.dss.model.tsl.TrustServiceStatusAndInformationExtensions;
import eu.europa.esig.dss.spi.tsl.TrustedListsCertificateSource;
import eu.europa.esig.dss.model.timedependent.TimeDependentValues;
import eu.europa.esig.dss.tsl.source.TLSource;
import eu.europa.esig.dss.validation.CertificateValidator;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.reports.CertificateReports;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DuplicatedStatusInTLValidationJobTest {

	private static final String URL = "URL_TO_DL";

	private static CertificateToken C1 = DSSUtils.loadCertificateFromBase64EncodedString(
			"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");

	private static CertificateToken C2 = DSSUtils.loadCertificateFromBase64EncodedString(
			"MIIEnTCCA4WgAwIBAgISESCGyNQKGGXAOA5j0SjVM9UMMA0GCSqGSIb3DQEBCwUAMFoxCzAJBgNVBAYTAkZSMRIwEAYDVQQKEwlLRVlORUNUSVMxHDAaBgNVBAsTE0tFWU5FQ1RJUyBmb3IgQWRvYmUxGTAXBgNVBAMTEEtFWU5FQ1RJUyBDRFMgQ0EwHhcNMTMwOTI3MDAwMDAwWhcNMTgxMDExMDcwMDAwWjBoMQswCQYDVQQGEwJGUjESMBAGA1UECgwJT1BFTlRSVVNUMRcwFQYDVQQLDA4wMDAyIDQ3ODIxNzMxODEsMCoGA1UEAwwjQ2xvdWQgU2lnbmluZyBQZXJzb25hbCBTaWduYXR1cmUgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC6ENIuJqI+wlda+RhaXJTnNrzk8Q08Jt9KRn4VkXdOsuLfMhURRTKLytqH4QYCM3AATH1KgMYU6ToPtMOWRy8aa//FE1B+RMPUPE1DCA4L42cJzaqzY8KYHQgGZa38Huw4fAHTotwp4v3mBcGoxNBCSk8ZnnNsKVBqrK8dVt4OeiVnKYSSyscY8c5mwhC5eZZvh7hm9H2uL+FXPyXxmAnV2OROhHmzI7fBt1fd1JrYWN4K0mGqzvFTX4lHimyD0waxXNLOHwbacPKRYY3kWXCBEMWHXacZgLlL5oJ0zfMq9X0ojH0rQsivGpwIlK2xX4O1mb4B4F8o9Rl13WDkxoAXAgMBAAGjggFNMIIBSTAOBgNVHQ8BAf8EBAMCAQYwFAYDVR0lBA0wCwYJKoZIhvcvAQEFMHYGA1UdIARvMG0wMgYEVR0gADAqMCgGCCsGAQUFBwIBFhxodHRwOi8vd3d3Lm9wZW50cnVzdC5jb20vUEMvMDcGCSqGSIb3LwECATAqMCgGCCsGAQUFBwIBFhxodHRwOi8vd3d3Lm9wZW50cnVzdC5jb20vUEMvMBIGA1UdEwEB/wQIMAYBAf8CAQAwVQYDVR0fBE4wTDBKoEigRoZEaHR0cDovL3RydXN0Y2VudGVyLWNybC5jZXJ0aWZpY2F0Mi5jb20vSW50ZXJuYWwvS0VZTkVDVElTX0NEU19DQS5jcmwwHQYDVR0OBBYEFJKm/sCn07vooB24naLnFNoqziHKMB8GA1UdIwQYMBaAFJ8ieNdxG94zsH/JIHqpqOBOYuP7MA0GCSqGSIb3DQEBCwUAA4IBAQCRCocOsDl1+5Z1JMRAwaPUL+XVzRzumHz1p74ngxJKuraEWSsHPLLph9f9DeYjcd/xQHqOm3omVurRckQD4RCXv1ZKHGnoyjSgJ0zd4tc5tqwdVwDpjYNDIxKeKD0IgnCI7d4ZwTvRHZpxpM78PxCEbcQFyaUOLq+mcKI+QPxsdG/aGClt/3Ux9NAJNo8h+8KZPlmVAeomjQSa6DT04i8tKoJu1sY8lx8eH6CcSglIO10JF5lxz2rmYHyG3r3QsfwDfqoH9bdxXjsTukiRCZh9Hg+lQMs8uONisqKtAJHch6GETxrmvv8TQL5B5aG1y+SiYUhMTKlYJBPgMEOhthkM");

	@TempDir
	File tempDir;

	@Test
	void test() {
		TrustedListsCertificateSource trustedListCertificateSource = getSynchronizedTLSource();

		assertNotEquals(C1, C2);
		assertTrue(C1.isEquivalent(C2));
		
		List<TrustProperties> listTrustPropertiesC1 = trustedListCertificateSource.getTrustServices(C1);
		assertEquals(2, listTrustPropertiesC1.size());

		TrustProperties trustProperties0 = listTrustPropertiesC1.get(0);
		TrustProperties trustProperties1 = listTrustPropertiesC1.get(1);
		assertNotEquals(trustProperties0, trustProperties1);
		assertEquals(trustProperties0.getTrustServiceProvider(), trustProperties1.getTrustServiceProvider());
		TimeDependentValues<TrustServiceStatusAndInformationExtensions> trustService0 = trustProperties0.getTrustService();
		TimeDependentValues<TrustServiceStatusAndInformationExtensions> trustService1 = trustProperties1.getTrustService();
		assertNotEquals(trustService0, trustService1);

		List<TrustServiceStatusAndInformationExtensions> result = new ArrayList<>();
		result.addAll(trustService0.getAfter(C1.getNotBefore()));
		result.addAll(trustService1.getAfter(C1.getNotBefore()));
		assertEquals(5, result.size());

		result = new ArrayList<>();
		result.addAll(trustService0.getAfter(C2.getNotBefore()));
		result.addAll(trustService1.getAfter(C2.getNotBefore()));
		assertEquals(5, result.size());

		List<TrustProperties> listTrustPropertiesC2 = trustedListCertificateSource.getTrustServices(C2);
		assertEquals(2, listTrustPropertiesC2.size());
	}

	@Test
	void certVal() {
		CertificateValidator certificateValidator = CertificateValidator.fromCertificate(C1);
		CertificateVerifier certificateVerifier = new CommonCertificateVerifier();
		certificateVerifier.setTrustedCertSources(getSynchronizedTLSource());
		certificateValidator.setCertificateVerifier(certificateVerifier);
		CertificateReports reports = certificateValidator.validate();

		DiagnosticData diagnosticData = reports.getDiagnosticData();
		CertificateWrapper certificateWrapper = diagnosticData.getUsedCertificateById(C1.getDSSIdAsString());
		assertNotNull(certificateWrapper);
		assertEquals(1, certificateWrapper.getTrustServiceProviders().size());
		assertEquals(5, certificateWrapper.getTrustServices().size());
	}

	private TrustedListsCertificateSource getSynchronizedTLSource() {
		TrustedListsCertificateSource trustedListCertificateSource = new TrustedListsCertificateSource();

		TLValidationJob tlValidationJob = new TLValidationJob();
		tlValidationJob.setOfflineDataLoader(getOfflineFileLoader());
		tlValidationJob.setTrustedListSources(getFrenchSource());
		tlValidationJob.setTrustedListCertificateSource(trustedListCertificateSource);
		tlValidationJob.offlineRefresh();
		return trustedListCertificateSource;
	}

	private TLSource getFrenchSource() {
		TLSource source = new TLSource();
		source.setUrl(URL);
		return source;
	}

	private DSSFileLoader getOfflineFileLoader() {

		FileCacheDataLoader offlineFileLoader = new FileCacheDataLoader();
		offlineFileLoader.setCacheExpirationTime(Long.MAX_VALUE);
		offlineFileLoader.setDataLoader(new MockDataLoader(getMap()));
		offlineFileLoader.setFileCacheDirectory(tempDir);
		return offlineFileLoader;
	}

	private Map<String, DSSDocument> getMap() {
		Map<String, DSSDocument> map = new HashMap<>();
		map.put(URL, new FileDocument("src/test/resources/fr-65-docusign.xml"));
		return map;
	}

}
