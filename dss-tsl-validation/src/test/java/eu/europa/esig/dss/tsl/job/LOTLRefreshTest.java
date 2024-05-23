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
package eu.europa.esig.dss.tsl.job;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.service.http.commons.FileCacheDataLoader;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.model.tsl.DownloadInfoRecord;
import eu.europa.esig.dss.model.tsl.LOTLInfo;
import eu.europa.esig.dss.model.tsl.ParsingInfoRecord;
import eu.europa.esig.dss.model.tsl.PivotInfo;
import eu.europa.esig.dss.model.tsl.TLValidationJobSummary;
import eu.europa.esig.dss.spi.tsl.TrustedListsCertificateSource;
import eu.europa.esig.dss.model.tsl.ValidationInfoRecord;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.spi.x509.CommonCertificateSource;
import eu.europa.esig.dss.tsl.source.LOTLSource;

public class LOTLRefreshTest {

	@TempDir
	File cacheDirectory;

	@Test
	public void test() {

		FileCacheDataLoader offlineFileLoader = getOfflineFileLoader(correctUrlMap());

		TLValidationJob job = new TLValidationJob();
		job.setListOfTrustedListSources(getLOTLSource());
		job.setOfflineDataLoader(offlineFileLoader);
		job.setTrustedListCertificateSource(new TrustedListsCertificateSource());

		job.setDebug(true);

		job.offlineRefresh();

		checks(job, Indication.TOTAL_PASSED);

		job.offlineRefresh();

		checks(job, Indication.TOTAL_PASSED);
	}

	@Test
	public void testMissingCert() {

		FileCacheDataLoader offlineFileLoader = getOfflineFileLoader(correctUrlMap());

		TLValidationJob job = new TLValidationJob();
		LOTLSource lotlSource = getLOTLSource();
		lotlSource.setCertificateSource(new CommonCertificateSource());
		job.setListOfTrustedListSources(lotlSource);
		job.setOfflineDataLoader(offlineFileLoader);
		job.setTrustedListCertificateSource(new TrustedListsCertificateSource());

		job.offlineRefresh();

		checks(job, Indication.INDETERMINATE);

		job.offlineRefresh();

		checks(job, Indication.INDETERMINATE);
	}

	@Test
	public void testWrongCert() {

		FileCacheDataLoader offlineFileLoader = getOfflineFileLoader(correctUrlMap());

		TLValidationJob job = new TLValidationJob();
		LOTLSource lotlSource = getLOTLSource();
		CommonCertificateSource certificateSource = new CommonCertificateSource();
		certificateSource.addCertificate(DSSUtils.loadCertificateFromBase64EncodedString(
				"MIIG3TCCBMWgAwIBAgIUWXcucAZpt2afsBLFzdE8OigaCREwDQYJKoZIhvcNAQELBQAwczELMAkGA1UEBhMCQkUxGTAXBgNVBGEMEE5UUkJFLTA1Mzc2OTgzMTgxIDAeBgNVBAoMF1F1b1ZhZGlzIFRydXN0bGluayBCVkJBMScwJQYDVQQDDB5RdW9WYWRpcyBCZWxnaXVtIElzc3VpbmcgQ0EgRzIwHhcNMTgwMzA3MTYwMDQzWhcNMjEwMzA3MTYxMDAwWjBwMQswCQYDVQQGEwJCRTETMBEGA1UECwwKREcgQ09OTkVDVDEbMBkGA1UEYQwSVkFUQkUtMDk0OS4zODMuMzQyMRwwGgYDVQQKDBNFdXJvcGVhbiBDb21taXNzaW9uMREwDwYDVQQDDAhFQ19DTkVDVDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAOjmsZD+GhI/ySvgMNd6OTqzIeOWQzCzDDW1LS5zx70hR+LOLaqIxQPpv8chiZOJgMEHpmmzjsvsDc42BvsX6Coz4GG4w80RtdMJXvaUqY6pvvo8zXAkqsHB/QgQSW3udTUIgLTy58pRwO8aFY77uvGsc3xpIZPQX0YMebiuyKeplXlmxwTOwHKbO3v0bNisIp7oU4mxgxQWdxuq4Ot6tYYp5wb6muc+sVyLH/5XGayXdeLzuCWsHyh60KhyLVtZftETFFwpZVYSkliMHc2DlMb/Y5EuIcQtHrzS3D4xnyT+LB0xvGaLaaTayCxL91bjL/d4H5G9UcChsqopdfZu4nsCAwEAAaOCAmowggJmMHcGCCsGAQUFBwEBBGswaTA4BggrBgEFBQcwAoYsaHR0cDovL3RydXN0LnF1b3ZhZGlzZ2xvYmFsLmNvbS9xdmJlY2FnMi5jcnQwLQYIKwYBBQUHMAGGIWh0dHA6Ly91dy5vY3NwLnF1b3ZhZGlzZ2xvYmFsLmNvbTAdBgNVHQ4EFgQU6BH8Rr4jtI8+97HXeN8Jl7jsRSQwHwYDVR0jBBgwFoAUh8m8MZcSenO7fsA9RVG0ASWVUaswWgYDVR0gBFMwUTBEBgorBgEEAb5YAYMQMDYwNAYIKwYBBQUHAgEWKGh0dHA6Ly93d3cucXVvdmFkaXNnbG9iYWwuY29tL3JlcG9zaXRvcnkwCQYHBACL7EABAzA7BgNVHR8ENDAyMDCgLqAshipodHRwOi8vY3JsLnF1b3ZhZGlzZ2xvYmFsLmNvbS9xdmJlY2FnMi5jcmwwDgYDVR0PAQH/BAQDAgbAMCkGA1UdJQQiMCAGCCsGAQUFBwMCBggrBgEFBQcDBAYKKwYBBAGCNwoDDDATBgoqhkiG9y8BAQkCBAUwAwIBATA0BgoqhkiG9y8BAQkBBCYwJAIBAYYfaHR0cDovL3RzLnF1b3ZhZGlzZ2xvYmFsLmNvbS9iZTCBiwYIKwYBBQUHAQMEfzB9MBUGCCsGAQUFBwsCMAkGBwQAi+xJAQIwCAYGBACORgEBMAgGBgQAjkYBBDATBgYEAI5GAQYwCQYHBACORgEGAjA7BgYEAI5GAQUwMTAvFilodHRwczovL3d3dy5xdW92YWRpc2dsb2JhbC5jb20vcmVwb3NpdG9yeRMCZW4wDQYJKoZIhvcNAQELBQADggIBAAfBVbR7SDdFccrLCXUTIpl5iu5bf7HcCZw1+xqaQ0cUHfYzZ51Nd51t40G856SuxjNHgt7G+8NmXwQvr01Zil4MJSxTbrNU8RaIjz2CvbvupuNXcLh3x6sCKmVk/p4EtY1pDMGYdEVDqUhoCgY5SnPQPDNIIOspRzWqv/Oc9dNcC7i9Aokp6IdNFc7PYy5CUI//+aPtlHG0zc56VuovGnxtkVSigPKKvRugyhjWaUBULZVVaW+7ebJRRlIRj9ssK0D+WGIGnZAIKceXU1W7UErxz0fFNlAn0KqsZ59BJCrzwAFuxe9OtwGrRsy6QGVbsQQFX/MN1PvXejzJI2nu7WlQ+dgUyuEXWNcTmSe+/S6iSNPpfe6K2YqcmSknsMzS+uyI8Fc0x+g0gkbvKKBpN7qkGY0rlGUhuZSd34w/QZjhgb2880ETRoWpmOlHRUBkJR3oC+arCNTrhIW6G/uPK15gCZU8VmKZc1g0VnhjFq33ryUu5GvQJReYXWQIIsTh4k88vWj1T+quxcXFuquJvfVcx/idXtkFTGSxRjV/0lD0akoMw4iQfbz01NSv2xoCROmGyL4RW566zuBlgU9oV734Fr0VYfwMafmGuBUG/B0EV2Rsc7/F2vUQkuakNoPjm6Ept3YIu7WY22lGwnAMN/Gq0xyQvrHrqA1n+XuKB/hq"));
		lotlSource.setCertificateSource(certificateSource);
		job.setListOfTrustedListSources(lotlSource);
		job.setOfflineDataLoader(offlineFileLoader);
		job.setTrustedListCertificateSource(new TrustedListsCertificateSource());

		job.offlineRefresh();

		checks(job, Indication.INDETERMINATE);

		job.offlineRefresh();

		checks(job, Indication.INDETERMINATE);
	}

	@Test
	public void testNullCertSource() {

		FileCacheDataLoader offlineFileLoader = getOfflineFileLoader(correctUrlMap());

		TLValidationJob job = new TLValidationJob();

		LOTLSource lotl = new LOTLSource();
		lotl.setUrl("EU");
		job.setListOfTrustedListSources(lotl);
		job.setOfflineDataLoader(offlineFileLoader);
		job.setTrustedListCertificateSource(new TrustedListsCertificateSource());

		job.offlineRefresh();

		TLValidationJobSummary summary = job.getSummary();
		LOTLInfo lotlInfo = summary.getLOTLInfos().get(0);
		assertTrue(lotlInfo.getValidationCacheInfo().isError());
	}

	private FileCacheDataLoader getOfflineFileLoader(Map<String, DSSDocument> urlMap) {
		FileCacheDataLoader offlineFileLoader = new FileCacheDataLoader();
		offlineFileLoader.setCacheExpirationTime(Long.MAX_VALUE);
		offlineFileLoader.setDataLoader(new MockDataLoader(urlMap));
		offlineFileLoader.setFileCacheDirectory(cacheDirectory);
		return offlineFileLoader;
	}

	private Map<String, DSSDocument> correctUrlMap() {
		Map<String, DSSDocument> urlMap = new HashMap<>();
		urlMap.put("EU", new FileDocument("src/test/resources/lotlCache/EU.xml"));
		return urlMap;
	}

	private void checks(TLValidationJob job, Indication expectedIndication) {
		TLValidationJobSummary summary = job.getSummary();
		assertNotNull(summary);
		assertEquals(1, summary.getNumberOfProcessedLOTLs());
		List<LOTLInfo> lotlInfos = summary.getLOTLInfos();
		assertEquals(1, lotlInfos.size());
		LOTLInfo lotlInfo = lotlInfos.get(0);
		DownloadInfoRecord downloadCacheInfo = lotlInfo.getDownloadCacheInfo();
		assertNotNull(downloadCacheInfo);
		assertNotNull(downloadCacheInfo.getLastStateTransitionTime());
		assertTrue(downloadCacheInfo.isSynchronized());
		ParsingInfoRecord parsingCacheInfo = lotlInfo.getParsingCacheInfo();
		assertNotNull(parsingCacheInfo);
		assertTrue(parsingCacheInfo.isSynchronized());

		assertEquals(5, parsingCacheInfo.getVersion());
		assertEquals(248, parsingCacheInfo.getSequenceNumber());

		ValidationInfoRecord validationCacheInfo = lotlInfo.getValidationCacheInfo();
		assertNotNull(validationCacheInfo);
		assertTrue(validationCacheInfo.isSynchronized());

		// LOTL
		assertEquals(expectedIndication, validationCacheInfo.getIndication());
		assertNotNull(validationCacheInfo.getSigningCertificate());
		assertNotNull(validationCacheInfo.getSigningTime());

		List<PivotInfo> pivotInfos = lotlInfo.getPivotInfos();
		assertEquals(0, pivotInfos.size());
	}

	private LOTLSource getLOTLSource() {
		LOTLSource lotl = new LOTLSource();
		lotl.setUrl("EU");
		CertificateSource certificateSource = new CommonCertificateSource();
		certificateSource.addCertificate(DSSUtils.loadCertificateFromBase64EncodedString(
				"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"));
		lotl.setCertificateSource(certificateSource);
		return lotl;
	}

}
