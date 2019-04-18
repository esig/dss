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
package eu.europa.esig.dss.tsl.service;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.client.http.MemoryDataLoader;
import eu.europa.esig.dss.client.http.commons.CommonsDataLoader;
import eu.europa.esig.dss.tsl.OtherTrustedList;
import eu.europa.esig.dss.tsl.TSLParserResult;
import eu.europa.esig.dss.tsl.TSLValidationModel;
import eu.europa.esig.dss.tsl.TSLValidationResult;
import eu.europa.esig.dss.tsl.TrustedListsCertificateSource;
import eu.europa.esig.dss.x509.CertificateToken;
import eu.europa.esig.dss.x509.KeyStoreCertificateSource;

public class TSLValidationJobTest {

	private static final Logger logger = LoggerFactory.getLogger(TSLValidationJobTest.class);

	private static final String USED_OJ_URL = "http://eur-lex.europa.eu/legal-content/EN/TXT/?uri=uriserv:OJ.C_.2016.233.01.0001.01.ENG";
	private static final String LOTL_URL = "https://ec.europa.eu/information_society/policy/esignature/trusted-list/tl-mp.xml";
	private KeyStoreCertificateSource dssKeyStore;

	@Before
	public void init() throws IOException {
		dssKeyStore = new KeyStoreCertificateSource(new File("src/test/resources/keystore.p12"), "PKCS12", "dss-password");
	}

	@Test
	public void test() {

		TSLRepository repository = new TSLRepository();
		repository.setTrustedListsCertificateSource(new TrustedListsCertificateSource());

		TSLValidationModel spain = repository.getByCountry("ES");
		assertNull(spain);

		TSLValidationJob job = new TSLValidationJob();
		job.setCheckLOTLSignature(true);
		job.setCheckTSLSignatures(true);
		job.setDataLoader(new CommonsDataLoader());
		job.setUsedOjKeystoreUrl(USED_OJ_URL);
		job.setLotlUrl(LOTL_URL);
		job.setLotlCode("EU");
		job.setOjContentKeyStore(dssKeyStore);
		job.setRepository(repository);

		job.refresh();
		
		assertNotNull(repository.getActualOjUrl());

		spain = repository.getByCountry("ES");
		assertNotNull(spain);
	}

	@Test
	public void testOnlyOneCountry() {

		TSLRepository repository = new TSLRepository();
		repository.setTrustedListsCertificateSource(new TrustedListsCertificateSource());

		TSLValidationModel france = repository.getByCountry("FR");
		assertNull(france);

		TSLValidationJob job = new TSLValidationJob();
		job.setCheckLOTLSignature(true);
		job.setCheckTSLSignatures(true);
		job.setDataLoader(new CommonsDataLoader());
		job.setUsedOjKeystoreUrl(USED_OJ_URL);
		job.setLotlUrl(LOTL_URL);
		job.setLotlCode("EU");
		job.setOjContentKeyStore(dssKeyStore);
		job.setRepository(repository);
		List<String> filterTerritories = new ArrayList<String>();
		filterTerritories.add("FR");
		job.setFilterTerritories(filterTerritories);

		job.refresh();

		france = repository.getByCountry("FR");
		assertNotNull(france);

		TSLValidationModel spain = repository.getByCountry("ES");
		assertNull(spain);
	}

	@Test
	public void testCache() {

		TSLRepository repository = new TSLRepository();
		repository.setTrustedListsCertificateSource(new TrustedListsCertificateSource());

		TSLValidationJob job = new TSLValidationJob();
		job.setCheckLOTLSignature(true);
		job.setCheckTSLSignatures(true);
		job.setDataLoader(new CommonsDataLoader());
		job.setUsedOjKeystoreUrl(USED_OJ_URL);
		job.setLotlUrl(LOTL_URL);
		job.setLotlCode("EU");
		job.setOjContentKeyStore(dssKeyStore);
		job.setRepository(repository);

		logger.info("***************** First load *****************");
		job.refresh();

		logger.info("***************** Second load *****************");
		job.refresh();
	}

	@Test
	public void testOtherTls() {

		TSLRepository repository = new TSLRepository();
		repository.setTrustedListsCertificateSource(new TrustedListsCertificateSource());

		TSLValidationModel peru = repository.getByCountry("PE");
		assertNull(peru);

		TSLValidationJob job = new TSLValidationJob();
		job.setCheckLOTLSignature(true);
		job.setCheckTSLSignatures(true);

		Map<String, byte[]> dataMap = new HashMap<String, byte[]>();
		dataMap.put("url-pe", DSSUtils.toByteArray(new FileDocument("src/test/resources/tsl-pe.xml")));
		job.setDataLoader(new MemoryDataLoader(dataMap));
		job.setRepository(repository);

		List<OtherTrustedList> otherTrustedLists = new ArrayList<OtherTrustedList>();
		OtherTrustedList otl = new OtherTrustedList();
		otl.setCountryCode("PE");
		otl.setUrl("url-pe");
		otl.setTrustStore(new PEKS());
		otherTrustedLists.add(otl);
		job.setOtherTrustedLists(otherTrustedLists);

		job.refresh();

		peru = repository.getByCountry("PE");
		assertNotNull(peru);

		assertFalse(peru.isLotl());
		assertTrue(peru.isCertificateSourceSynchronized());

		TSLParserResult parseResult = peru.getParseResult();
		assertNotNull(parseResult);
		assertNotNull(parseResult.getIssueDate());
		assertNotNull(parseResult.getNextUpdateDate());
		assertNotNull(parseResult.getServiceProviders());

		assertTrue(parseResult.getPointers().isEmpty());

		TSLValidationResult validationResult = peru.getValidationResult();
		assertNotNull(validationResult);
		assertTrue(validationResult.isValid());
	}

	private class PEKS extends KeyStoreCertificateSource {

		private static final long serialVersionUID = 7724428818822120973L;

		public PEKS() {
			super("PKCS12", "");
		}

		@Override
		public List<CertificateToken> getCertificates() {
			return Arrays.asList(DSSUtils.loadCertificateFromBase64EncodedString(
					"MIIELDCCAhSgAwIBAgIBAjANBgkqhkiG9w0BAQsFADBRMSEwHwYDVQQDExhJTkRFQ09QSSBBQUMgUkFJWiBTSEEyNTYxDDAKBgNVBAsTA0NGRTERMA8GA1UEChMISU5ERUNPUEkxCzAJBgNVBAYTAlBFMB4XDTE3MDQyMDIxNTMzNloXDTIwMDQyMDIxNTMzNlowTjEeMBwGA1UEAxMVVFNMIFN1c2NyaXB0b3IgU0hBMjU2MQwwCgYDVQQLEwNDRkUxETAPBgNVBAoTCElOREVDT1BJMQswCQYDVQQGEwJQRTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL0tVx8VXgQFih1IPtnvBl9UO9EnctN3zuWwEultjc5ig/rC01oAuWf8Kp271BLEMsnFJD9w+tdPrW2bxu7V7AgDsq0httwwqEmBA950/cOyaaJkQ5b04eqvIWlU7D3NrGbudeI1DHI3h3Q/h4xo1xWdag/UmqfBBs6xSO7P7E2bdn7M2D+8ZqY4JV9YchphHdT9RSGNHgVSCUjN1bg67Cs593Rc6haCgSWeDaeWnaEXlzyqgaSINbTf6+reDItHqKa78gZU6JqlPRAPs1rdnQGPLVJTdfKduF9ZbzcmctqtENeG5yFR4wcBf/1ngxlIRXnNHQE/RRYX5iB0ZL9fosMCAwCrhaMSMBAwDgYDVR0PAQH/BAQDAgCAMA0GCSqGSIb3DQEBCwUAA4ICAQCMcAgkvdBGkN2qECnwyq/p7gZbKKJ5eKnsmSnQ2xYJ7UfTnFwSG5PlLeD2erVLCLlM8wzp1Iea43PDhSP8aH0QOPsxgtiPlUT0l1khG9RYSpw1EatLHlRPACCvZRNvQ9nSSBwG3qG7jzTUGU6WvSifvfN/d5lwzA/skulvOk6nmYvaOq1FOToJIy01WaGcX0yV8C/d1qmDzm77asrtRoSQA6depQ63OPbuGSVDqpHjiAZmr8HiSH3vBpcm66kjPKAnESmE0M5s6zjHpLa1RvYBYTY5luKAQdim1wIMDmI+vf+u7gQkZzqG0+TJos2o7j3AOuyn9gOuhV7NQZPUV/EKoLRolRqZg31q/XhptoEX61RXV8ggyEHKQG12xRa2RBOwEqLWX76H6AwBG/DqZWiWkSrftFfwPnxsmvxwMzNLw3EV1DXfHxruoy12MPKlbmMtVGkh0G3Mf8b3iUOPShenAQFg2FzUrZg0oXUZIJfg6JtgoHy3l8QffCpYfP088cEdvdWWkAN4L34BfojRCjqcDsMyx+9GMv4ODlDPijIwrpGtHkbmk0Rrti8rhzdeAFVOBcvWRYkW3esHvXhf5D3zokjYUiUnQyVBLS3t5zwOir14t82qC/KK6b53p01Fp3Jc3Mrt1Gzrr7wx/IDeQDBfHuj47pWwUuwEuJR64Lo+4w=="));
		}

	}

	@Test
	public void testNothing() {

		TSLRepository repository = new TSLRepository();
		repository.setTrustedListsCertificateSource(new TrustedListsCertificateSource());

		TSLValidationModel aaCountry = repository.getByCountry("AA");
		assertNull(aaCountry);

		TSLValidationJob job = new TSLValidationJob();
		job.setRepository(repository);

		job.refresh();

		aaCountry = repository.getByCountry("AA");
		assertNull(aaCountry);
	}

	@Test
	public void initRepository() {

		TSLRepository repository = new TSLRepository();
		repository.setCacheDirectoryPath("src/test/resources/tsls");
		repository.setTrustedListsCertificateSource(new TrustedListsCertificateSource());

		TSLValidationModel portugal = repository.getByCountry("PT");
		assertNull(portugal);

		TSLValidationJob job = new TSLValidationJob();
		job.setRepository(repository);

		job.initRepository();

		portugal = repository.getByCountry("PT");
		assertNotNull(portugal);

	}
	
	@Test
	public void testOldOjUrl() {

		TSLRepository repository = new TSLRepository();
		repository.setTrustedListsCertificateSource(new TrustedListsCertificateSource());

		TSLValidationModel spain = repository.getByCountry("ES");
		assertNull(spain);

		TSLValidationJob job = new TSLValidationJob();
		job.setCheckLOTLSignature(true);
		job.setCheckTSLSignatures(true);
		job.setDataLoader(new CommonsDataLoader());
		job.setUsedOjKeystoreUrl("http://eur-lex.europa.eu/legal-content/EN/TXT/?uri=uriserv:OJ.C_.2014.175.01.0001.01.ENG");
		job.setLotlUrl(LOTL_URL);
		job.setLotlCode("EU");
		job.setOjContentKeyStore(dssKeyStore);
		job.setRepository(repository);

		job.refresh();
		
		assertNotNull(repository.getActualOjUrl());
		
	}
	
	@Test
	public void testWrongDomainName() {

		TSLRepository repository = new TSLRepository();
		repository.setTrustedListsCertificateSource(new TrustedListsCertificateSource());

		TSLValidationModel spain = repository.getByCountry("ES");
		assertNull(spain);

		TSLValidationJob job = new TSLValidationJob();
		job.setCheckLOTLSignature(true);
		job.setCheckTSLSignatures(true);
		job.setDataLoader(new CommonsDataLoader());
		job.setUsedOjKeystoreUrl("wrong-dns.eu/name");
		job.setLotlUrl(LOTL_URL);
		job.setLotlCode("EU");
		job.setOjContentKeyStore(dssKeyStore);
		job.setRepository(repository);

		job.refresh();
		
		assertNotNull(repository.getActualOjUrl());
		
	}
	
	public void testNullOjUrl() {

		TSLRepository repository = new TSLRepository();
		repository.setTrustedListsCertificateSource(new TrustedListsCertificateSource());

		TSLValidationModel spain = repository.getByCountry("ES");
		assertNull(spain);

		TSLValidationJob job = new TSLValidationJob();
		job.setCheckLOTLSignature(true);
		job.setCheckTSLSignatures(true);
		job.setDataLoader(new CommonsDataLoader());
		job.setUsedOjKeystoreUrl(null);
		job.setLotlUrl(LOTL_URL);
		job.setLotlCode("EU");
		job.setOjContentKeyStore(dssKeyStore);
		job.setRepository(repository);

		job.refresh();
		
		assertNotNull(repository.getActualOjUrl());
		
	}

}
