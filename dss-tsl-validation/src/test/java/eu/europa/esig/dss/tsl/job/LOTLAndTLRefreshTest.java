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
import eu.europa.esig.dss.model.tsl.TLInfo;
import eu.europa.esig.dss.model.tsl.TLValidationJobSummary;
import eu.europa.esig.dss.spi.tsl.TrustedListsCertificateSource;
import eu.europa.esig.dss.model.tsl.ValidationInfoRecord;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.spi.x509.CommonCertificateSource;
import eu.europa.esig.dss.tsl.source.LOTLSource;
import eu.europa.esig.dss.tsl.source.TLSource;

class LOTLAndTLRefreshTest {

	@TempDir
	File cacheDirectory;

	@Test
	void test() {

		FileCacheDataLoader offlineFileLoader = getOfflineFileLoader(correctUrlMap());

		TLValidationJob job = new TLValidationJob();
		job.setListOfTrustedListSources(europeanLOTL());
		job.setTrustedListSources(peruvianTrustedList());
		job.setOfflineDataLoader(offlineFileLoader);
		job.setTrustedListCertificateSource(new TrustedListsCertificateSource());

		job.setDebug(true);

		job.offlineRefresh();

		checks(job, Indication.TOTAL_PASSED);

		job.offlineRefresh();

		checks(job, Indication.TOTAL_PASSED);
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
		urlMap.put("PE", new FileDocument("src/test/resources/tsl-pe.xml"));
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

		assertEquals(31, lotlInfo.getTLInfos().size());

		assertEquals(1, summary.getOtherTLInfos().size());

		TLInfo tlInfo = summary.getOtherTLInfos().get(0);

		downloadCacheInfo = tlInfo.getDownloadCacheInfo();
		assertNotNull(downloadCacheInfo);
		assertNotNull(downloadCacheInfo.getLastStateTransitionTime());
		assertTrue(downloadCacheInfo.isSynchronized());

		parsingCacheInfo = tlInfo.getParsingCacheInfo();
		assertNotNull(parsingCacheInfo);
		assertTrue(parsingCacheInfo.isError());
		assertNotNull(parsingCacheInfo.getExceptionMessage());
		assertNotNull(parsingCacheInfo.getExceptionStackTrace());

		validationCacheInfo = tlInfo.getValidationCacheInfo();
		assertNotNull(validationCacheInfo);
		assertTrue(validationCacheInfo.isSynchronized());
		// assertTrue(validationCacheInfo.isValid()); // TODO : update Peruvian TL
		assertNotNull(validationCacheInfo.getSigningCertificate());
		assertNotNull(validationCacheInfo.getSigningTime());
	}

	private LOTLSource europeanLOTL() {
		LOTLSource lotl = new LOTLSource();
		lotl.setUrl("EU");
		CertificateSource certificateSource = new CommonCertificateSource();
		certificateSource.addCertificate(DSSUtils.loadCertificateFromBase64EncodedString(
				"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"));
		lotl.setCertificateSource(certificateSource);
		return lotl;
	}

	private TLSource peruvianTrustedList() {
		TLSource tl = new TLSource();
		tl.setUrl("PE");

		CertificateSource certificateSource = new CommonCertificateSource();
		certificateSource.addCertificate(DSSUtils.loadCertificateFromBase64EncodedString(
				"MIIELDCCAhSgAwIBAgIBAjANBgkqhkiG9w0BAQsFADBRMSEwHwYDVQQDExhJTkRFQ09QSSBBQUMgUkFJWiBTSEEyNTYxDDAKBgNVBAsTA0NGRTERMA8GA1UEChMISU5ERUNPUEkxCzAJBgNVBAYTAlBFMB4XDTE3MDQyMDIxNTMzNloXDTIwMDQyMDIxNTMzNlowTjEeMBwGA1UEAxMVVFNMIFN1c2NyaXB0b3IgU0hBMjU2MQwwCgYDVQQLEwNDRkUxETAPBgNVBAoTCElOREVDT1BJMQswCQYDVQQGEwJQRTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL0tVx8VXgQFih1IPtnvBl9UO9EnctN3zuWwEultjc5ig/rC01oAuWf8Kp271BLEMsnFJD9w+tdPrW2bxu7V7AgDsq0httwwqEmBA950/cOyaaJkQ5b04eqvIWlU7D3NrGbudeI1DHI3h3Q/h4xo1xWdag/UmqfBBs6xSO7P7E2bdn7M2D+8ZqY4JV9YchphHdT9RSGNHgVSCUjN1bg67Cs593Rc6haCgSWeDaeWnaEXlzyqgaSINbTf6+reDItHqKa78gZU6JqlPRAPs1rdnQGPLVJTdfKduF9ZbzcmctqtENeG5yFR4wcBf/1ngxlIRXnNHQE/RRYX5iB0ZL9fosMCAwCrhaMSMBAwDgYDVR0PAQH/BAQDAgCAMA0GCSqGSIb3DQEBCwUAA4ICAQCMcAgkvdBGkN2qECnwyq/p7gZbKKJ5eKnsmSnQ2xYJ7UfTnFwSG5PlLeD2erVLCLlM8wzp1Iea43PDhSP8aH0QOPsxgtiPlUT0l1khG9RYSpw1EatLHlRPACCvZRNvQ9nSSBwG3qG7jzTUGU6WvSifvfN/d5lwzA/skulvOk6nmYvaOq1FOToJIy01WaGcX0yV8C/d1qmDzm77asrtRoSQA6depQ63OPbuGSVDqpHjiAZmr8HiSH3vBpcm66kjPKAnESmE0M5s6zjHpLa1RvYBYTY5luKAQdim1wIMDmI+vf+u7gQkZzqG0+TJos2o7j3AOuyn9gOuhV7NQZPUV/EKoLRolRqZg31q/XhptoEX61RXV8ggyEHKQG12xRa2RBOwEqLWX76H6AwBG/DqZWiWkSrftFfwPnxsmvxwMzNLw3EV1DXfHxruoy12MPKlbmMtVGkh0G3Mf8b3iUOPShenAQFg2FzUrZg0oXUZIJfg6JtgoHy3l8QffCpYfP088cEdvdWWkAN4L34BfojRCjqcDsMyx+9GMv4ODlDPijIwrpGtHkbmk0Rrti8rhzdeAFVOBcvWRYkW3esHvXhf5D3zokjYUiUnQyVBLS3t5zwOir14t82qC/KK6b53p01Fp3Jc3Mrt1Gzrr7wx/IDeQDBfHuj47pWwUuwEuJR64Lo+4w=="));
		tl.setCertificateSource(certificateSource);
		return tl;
	}

}
