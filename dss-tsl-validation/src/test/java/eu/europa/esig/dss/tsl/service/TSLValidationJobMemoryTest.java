package eu.europa.esig.dss.tsl.service;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.spi.client.http.MemoryDataLoader;
import eu.europa.esig.dss.spi.tsl.TrustedListsCertificateSource;
import eu.europa.esig.dss.spi.x509.KeyStoreCertificateSource;
import eu.europa.esig.dss.tsl.TSLParserResult;
import eu.europa.esig.dss.tsl.TSLValidationModel;
import eu.europa.esig.dss.tsl.TSLValidationResult;

public class TSLValidationJobMemoryTest {
	
	private static Map<String, byte[]> urlMap;
	private static KeyStoreCertificateSource dssKeyStore;
	
	private static TSLRepository repository;
	private static TSLValidationJob job;

	private static final String USED_OJ_URL = "http://eur-lex.europa.eu/legal-content/EN/TXT/?uri=uriserv:OJ.C_.2016.233.01.0001.01.ENG";
	private static final String LOTL_URL = "https://ec.europa.eu/tools/lotl/eu-lotl.xml";
	
	private static final String CZ_URL = "https://tsl.gov.cz/publ/TSL_CZ.xtsl";

	@BeforeAll
	public static void init() throws IOException {
		dssKeyStore = new KeyStoreCertificateSource(new File("src/test/resources/keystore.p12"), "PKCS12", "dss-password");
		
		urlMap = new HashMap<String, byte[]>();
		urlMap.put(LOTL_URL, Files.readAllBytes(Paths.get("src/test/resources/lotlCache/eu-lotl_original.xml")));
		
		urlMap.put("https://ec.europa.eu/information_society/policy/esignature/trusted-list/tl-pivot-247-mp.xml", 
				Files.readAllBytes(Paths.get("src/test/resources/lotlCache/tl_pivot_247_mp.xml")));
		urlMap.put("https://ec.europa.eu/information_society/policy/esignature/trusted-list/tl-pivot-226-mp.xml", 
				Files.readAllBytes(Paths.get("src/test/resources/lotlCache/tl_pivot_226_mp.xml")));
		urlMap.put("https://ec.europa.eu/information_society/policy/esignature/trusted-list/tl-pivot-191-mp.xml", 
				Files.readAllBytes(Paths.get("src/test/resources/lotlCache/tl_pivot_191_mp.xml")));
		urlMap.put("https://ec.europa.eu/information_society/policy/esignature/trusted-list/tl-pivot-172-mp.xml", 
				Files.readAllBytes(Paths.get("src/test/resources/lotlCache/tl_pivot_172_mp.xml")));
		
		urlMap.put("https://www.signatur.rtr.at/currenttl.xml", Files.readAllBytes(Paths.get("src/test/resources/lotlCache/AT.xml")));
		urlMap.put("https://tsl.belgium.be/tsl-be.xml", Files.readAllBytes(Paths.get("src/test/resources/lotlCache/BE.xml")));
		urlMap.put("https://crc.bg/files/_en/TSL_BG.xml", Files.readAllBytes(Paths.get("src/test/resources/lotlCache/BG.xml")));
		urlMap.put("http://www.mcw.gov.cy/mcw/dec/dec.nsf/all/B28C11BBFDBAC045C2257E0D002937E9/$file/TSL-CY-sign.xml", Files.readAllBytes(Paths.get("src/test/resources/lotlCache/CY.xml")));
		urlMap.put(CZ_URL, Files.readAllBytes(Paths.get("src/test/resources/lotlCache/CZ.xml")));
		urlMap.put("https://www.nrca-ds.de/st/TSL-XML.xml", Files.readAllBytes(Paths.get("src/test/resources/lotlCache/DE.xml")));
		urlMap.put("https://www.digst.dk/TSLDKxml", Files.readAllBytes(Paths.get("src/test/resources/lotlCache/DK.xml")));
		urlMap.put("https://sr.riik.ee/tsl/estonian-tsl.xml", Files.readAllBytes(Paths.get("src/test/resources/lotlCache/ES.xml"))); // wrong country code
		urlMap.put("https://www.eett.gr/tsl/EL-TSL.xml", Files.readAllBytes(Paths.get("src/test/resources/lotlCache/EL.xml")));
		urlMap.put("https://sede.minetur.gob.es/Prestadores/TSL/TSL.xml", Files.readAllBytes(Paths.get("src/test/resources/lotlCache/ES.xml")));
		urlMap.put("https://dp.trustedlist.fi/fi-tl.xml", Files.readAllBytes(Paths.get("src/test/resources/lotlCache/FI.xml")));
		urlMap.put("http://www.ssi.gouv.fr/eidas/TL-FR.xml", Files.readAllBytes(Paths.get("src/test/resources/lotlCache/FR.xml")));
		urlMap.put("https://www.mingo.hr/TLS/TSL-HR.xml", Files.readAllBytes(Paths.get("src/test/resources/lotlCache/HR.xml")));
		urlMap.put("http://www.nmhh.hu/tl/pub/HU_TL.xml", Files.readAllBytes(Paths.get("src/test/resources/lotlCache/HU.xml")));
		urlMap.put("http://files.dcenr.gov.ie/rh/Irelandtslsigned.xml", Files.readAllBytes(Paths.get("src/test/resources/lotlCache/IE.xml")));
		urlMap.put("http://www.neytendastofa.is/library/Files/TSl/tsl.xml", Files.readAllBytes(Paths.get("src/test/resources/lotlCache/IS.xml")));
		urlMap.put("https://eidas.agid.gov.it/TL/TSL-IT.xml", Files.readAllBytes(Paths.get("src/test/resources/lotlCache/IT.xml")));
		urlMap.put("https://www.llv.li/files/ak/xml-llv-ak-tsl.xml", Files.readAllBytes(Paths.get("src/test/resources/lotlCache/LI.xml")));
		urlMap.put("https://elektroninisparasas.lt/LT-TSL.xml", Files.readAllBytes(Paths.get("src/test/resources/lotlCache/LT.xml")));
		urlMap.put("https://portail-qualite.public.lu/content/dam/qualite/fr/publications/confiance-numerique/liste-confiance-nationale/tsl-xml/tsl.xml", Files.readAllBytes(Paths.get("src/test/resources/lotlCache/LU.xml")));
		urlMap.put("https://trustlist.gov.lv/tsl/latvian-tsl.xml", Files.readAllBytes(Paths.get("src/test/resources/lotlCache/LV.xml")));
		urlMap.put("https://www.mca.org.mt/tsl/MT_TSL.xml", Files.readAllBytes(Paths.get("src/test/resources/lotlCache/MT.xml")));
		urlMap.put("https://www.agentschaptelecom.nl/binaries/agentschap-telecom/documenten/publicaties/2018/januari/01/digitale-statuslijst-van-vertrouwensdiensten/current-tsl.xml", Files.readAllBytes(Paths.get("src/test/resources/lotlCache/NL.xml")));
		urlMap.put("https://tl-norway.no/TSL/NO_TSL.XML", Files.readAllBytes(Paths.get("src/test/resources/lotlCache/NO.xml")));
		urlMap.put("https://www.nccert.pl/tsl/PL_TSL.xml", Files.readAllBytes(Paths.get("src/test/resources/lotlCache/PL.xml")));
		urlMap.put("https://www.gns.gov.pt/media/1894/TSLPT.xml", Files.readAllBytes(Paths.get("src/test/resources/lotlCache/PT.xml")));
		// RO is missed
		urlMap.put("https://trustedlist.pts.se/SE-TL.xml", Files.readAllBytes(Paths.get("src/test/resources/lotlCache/SE.xml")));
		urlMap.put("http://www.mju.gov.si/fileadmin/mju.gov.si/pageuploads/DID/Informacijska_druzba/eIDAS/SI_TL.xml", Files.readAllBytes(Paths.get("src/test/resources/lotlCache/SI.xml")));
		urlMap.put("http://tl.nbu.gov.sk/kca/tsl/tsl.xml", Files.readAllBytes(Paths.get("src/test/resources/lotlCache/SK.xml")));
		urlMap.put("https://www.tscheme.org/UK_TSL/TSL-UKsigned.xml", Files.readAllBytes(Paths.get("src/test/resources/lotlCache/UK.xml")));
		urlMap.put("https://www.tscheme.org/UK_TSL/TSL-UKsigned.xml", Files.readAllBytes(Paths.get("src/test/resources/lotlCache/UK.xml")));
		
		repository = new TSLRepository();
		repository.setTrustedListsCertificateSource(new TrustedListsCertificateSource());

		job = new TSLValidationJob();
		job.setCheckLOTLSignature(true);
		job.setCheckTSLSignatures(true);
		job.setDataLoader(new MemoryDataLoader(urlMap));
		job.setOjUrl(USED_OJ_URL);
		job.setLotlUrl(LOTL_URL);
		job.setLotlCode("EU");
		job.setOjContentKeyStore(dssKeyStore);
		job.setRepository(repository);
	}

	@Test
	public void test() throws IOException {
		repository.clearRepository();
		
		TSLValidationModel czech = repository.getByCountry("CZ");
		assertNull(czech);

		job.setDataLoader(new MemoryDataLoader(urlMap));
		job.refresh();
		
		assertNotNull(repository.getActualOjUrl());

		czech = repository.getByCountry("CZ");
		assertNotNull(czech);
		TSLParserResult parseResultCZ = czech.getParseResult();
		assertNotNull(parseResultCZ);
		TSLValidationResult validationResultCZ = czech.getValidationResult();
		assertNotNull(validationResultCZ);
		assertTrue(validationResultCZ.isValid());
		
		TSLValidationModel estonia = repository.getByCountry("EE");
		assertNotNull(estonia);
		TSLParserResult parseResultEE = estonia.getParseResult();
		assertNull(parseResultEE); // TODO: must not be null ???
		TSLValidationResult validationResultEE = estonia.getValidationResult();
		assertNotNull(validationResultEE); // TODO: must be null ???
		TSLValidationModel romania = repository.getByCountry("RO");
		assertNotNull(romania);
		TSLParserResult parseResultRO = romania.getParseResult();
		assertNull(parseResultRO);
		TSLValidationResult validationResultRO = romania.getValidationResult();
		assertNull(validationResultRO);

		TSLValidationModel eu = repository.getByCountry("EU");
		assertNotNull(eu);
		TSLParserResult parseResultEU = eu.getParseResult();
		assertNotNull(parseResultEU);
		TSLValidationResult validationResultEU = eu.getValidationResult();
		assertNotNull(validationResultEU);
		assertTrue(validationResultEU.isValid());
	}
	
	@Test
	public void tlBrokenSigTest() throws IOException {
		repository.clearRepository();
		
		HashMap<String, byte[]> localUrlMap = new HashMap<String, byte[]>();
		localUrlMap.putAll(urlMap);
		localUrlMap.put(CZ_URL, Files.readAllBytes(Paths.get("src/test/resources/lotlCache/CZ_broken-sig.xml")));
		job.setDataLoader(new MemoryDataLoader(localUrlMap));
		
		job.refresh();

		TSLValidationModel czech = repository.getByCountry("CZ");
		assertNotNull(czech);
		TSLParserResult parseResultCZ = czech.getParseResult();
		assertNotNull(parseResultCZ);
		TSLValidationResult validationResultCZ = czech.getValidationResult();
		assertNotNull(validationResultCZ);
		assertFalse(validationResultCZ.isValid());
	}
	
	@Test
	public void tlEmptyTest() throws IOException {
		repository.clearRepository();
		
		HashMap<String, byte[]> localUrlMap = new HashMap<String, byte[]>();
		localUrlMap.putAll(urlMap);
		localUrlMap.put(CZ_URL, Files.readAllBytes(Paths.get("src/test/resources/lotlCache/CZ_empty.xml")));
		job.setDataLoader(new MemoryDataLoader(localUrlMap));
		
		job.refresh();

		TSLValidationModel czech = repository.getByCountry("CZ");
		assertNotNull(czech);
		TSLParserResult parseResultCZ = czech.getParseResult();
		assertNull(parseResultCZ);
		TSLValidationResult validationResultCZ = czech.getValidationResult();
		assertNull(validationResultCZ);
	}
	
	@Test
	public void tlNotParsableTest() throws IOException {
		repository.clearRepository();
		
		HashMap<String, byte[]> localUrlMap = new HashMap<String, byte[]>();
		localUrlMap.putAll(urlMap);
		localUrlMap.put(CZ_URL, Files.readAllBytes(Paths.get("src/test/resources/lotlCache/CZ_not-parsable.xml")));
		job.setDataLoader(new MemoryDataLoader(localUrlMap));
		
		job.refresh();

		TSLValidationModel czech = repository.getByCountry("CZ");
		assertNotNull(czech);
		TSLParserResult parseResultCZ = czech.getParseResult();
		assertNull(parseResultCZ);
		TSLValidationResult validationResultCZ = czech.getValidationResult();
		assertNull(validationResultCZ);
	}
	
	@Test
	public void tlNoSigTest() throws IOException {
		repository.clearRepository();
		
		HashMap<String, byte[]> localUrlMap = new HashMap<String, byte[]>();
		localUrlMap.putAll(urlMap);
		localUrlMap.put(CZ_URL, Files.readAllBytes(Paths.get("src/test/resources/lotlCache/CZ_no-sig.xml")));
		job.setDataLoader(new MemoryDataLoader(localUrlMap));
		
		job.refresh();

		TSLValidationModel czech = repository.getByCountry("CZ");
		assertNotNull(czech);
		TSLParserResult parseResultCZ = czech.getParseResult();
		assertNotNull(parseResultCZ);
		TSLValidationResult validationResultCZ = czech.getValidationResult();
		assertNotNull(validationResultCZ);
		assertFalse(validationResultCZ.isValid());
	}
	
	@Test
	public void tlPdfTest() throws IOException {
		repository.clearRepository();
		
		HashMap<String, byte[]> localUrlMap = new HashMap<String, byte[]>();
		localUrlMap.putAll(urlMap);
		localUrlMap.put(CZ_URL, Files.readAllBytes(Paths.get("src/test/resources/lotlCache/CZ.pdf")));
		job.setDataLoader(new MemoryDataLoader(localUrlMap));
		
		job.refresh();

		TSLValidationModel czech = repository.getByCountry("CZ");
		assertNotNull(czech);
		TSLParserResult parseResultCZ = czech.getParseResult();
		assertNull(parseResultCZ);
		TSLValidationResult validationResultCZ = czech.getValidationResult();
		assertNull(validationResultCZ);
	}
	
	@Test
	public void tlImageTest() throws IOException {
		repository.clearRepository();
		
		HashMap<String, byte[]> localUrlMap = new HashMap<String, byte[]>();
		localUrlMap.putAll(urlMap);
		localUrlMap.put(CZ_URL, Files.readAllBytes(Paths.get("src/test/resources/lotlCache/CZ.png")));
		job.setDataLoader(new MemoryDataLoader(localUrlMap));
		
		job.refresh();

		TSLValidationModel czech = repository.getByCountry("CZ");
		assertNotNull(czech);
		TSLParserResult parseResultCZ = czech.getParseResult();
		assertNull(parseResultCZ);
		TSLValidationResult validationResultCZ = czech.getValidationResult();
		assertNull(validationResultCZ);
	}
	
	@Test
	public void lotlBrokenSigTest() throws IOException {
		repository.clearRepository();
		
		HashMap<String, byte[]> localUrlMap = new HashMap<String, byte[]>();
		localUrlMap.putAll(urlMap);
		localUrlMap.put(LOTL_URL, Files.readAllBytes(Paths.get("src/test/resources/lotlCache/eu-lotl_broken-sig.xml")));
		job.setDataLoader(new MemoryDataLoader(localUrlMap));
		
		job.refresh();

		TSLValidationModel czech = repository.getByCountry("CZ");
		assertNotNull(czech);
		TSLValidationResult validationResultCZ = czech.getValidationResult();
		assertNotNull(validationResultCZ);
		assertTrue(validationResultCZ.isValid());
		TSLValidationModel spain = repository.getByCountry("ES");
		assertNotNull(spain);
		TSLValidationResult validationResultES = spain.getValidationResult();
		assertNotNull(validationResultES);
		assertTrue(validationResultES.isValid());

		TSLValidationModel eu = repository.getByCountry("EU");
		assertNotNull(eu);
		TSLParserResult parseResultEU = eu.getParseResult();
		assertNotNull(parseResultEU);
		TSLValidationResult validationResultEU = eu.getValidationResult();
		assertNotNull(validationResultEU);
		assertFalse(validationResultEU.isValid());
	}
	
	@Test
	public void lotlNotParsableTest() throws IOException {
		repository.clearRepository();
		
		HashMap<String, byte[]> localUrlMap = new HashMap<String, byte[]>();
		localUrlMap.putAll(urlMap);
		localUrlMap.put(LOTL_URL, Files.readAllBytes(Paths.get("src/test/resources/lotlCache/eu-lotl_not-parsable.xml")));
		job.setDataLoader(new MemoryDataLoader(localUrlMap));
		
		job.refresh();

		TSLValidationModel czech = repository.getByCountry("CZ");
		assertNull(czech);

		TSLValidationModel eu = repository.getByCountry("EU");
		assertNotNull(eu);
		TSLParserResult parseResultEU = eu.getParseResult();
		assertNull(parseResultEU);
		TSLValidationResult validationResultEU = eu.getValidationResult();
		assertNull(validationResultEU);
	}
	
	@Test
	public void lotlXmlDeclarationRemovedTest() throws IOException {
		repository.clearRepository();
		
		HashMap<String, byte[]> localUrlMap = new HashMap<String, byte[]>();
		localUrlMap.putAll(urlMap);
		localUrlMap.put(LOTL_URL, Files.readAllBytes(Paths.get("src/test/resources/lotlCache/eu-lotl_xml-directive-removed.xml")));
		job.setDataLoader(new MemoryDataLoader(localUrlMap));
		
		job.refresh();

		TSLValidationModel czech = repository.getByCountry("CZ");
		assertNotNull(czech);

		TSLValidationModel eu = repository.getByCountry("EU");
		assertNotNull(eu);
		TSLParserResult parseResultEU = eu.getParseResult();
		assertNotNull(parseResultEU);
		TSLValidationResult validationResultEU = eu.getValidationResult();
		assertNotNull(validationResultEU);
		assertTrue(validationResultEU.isValid());
	}
	
	@Test
	public void pivotTest() throws IOException {
		repository.clearRepository();
		
		HashMap<String, byte[]> localUrlMap = new HashMap<String, byte[]>();
		localUrlMap.putAll(urlMap);
		localUrlMap.put(LOTL_URL, Files.readAllBytes(Paths.get("src/test/resources/lotlCache/tl_pivot_247_mp.xml")));
		job.setDataLoader(new MemoryDataLoader(localUrlMap));
		
		job.refresh();

		TSLValidationModel czech = repository.getByCountry("CZ");
		assertNotNull(czech);

		TSLValidationModel eu = repository.getByCountry("EU");
		assertNotNull(eu);
		TSLParserResult parseResultEU = eu.getParseResult();
		assertNotNull(parseResultEU);
		TSLValidationResult validationResultEU = eu.getValidationResult();
		assertNotNull(validationResultEU);
		assertTrue(eu.isLotl());
		assertTrue(validationResultEU.isValid());
	}
	
	@Test
	public void pivotBrokenSigTest() throws IOException {
		repository.clearRepository();
		
		HashMap<String, byte[]> localUrlMap = new HashMap<String, byte[]>();
		localUrlMap.putAll(urlMap);
		localUrlMap.put(LOTL_URL, Files.readAllBytes(Paths.get("src/test/resources/lotlCache/tl_pivot_247_mp_broken-sig.xml")));
		job.setDataLoader(new MemoryDataLoader(localUrlMap));
		
		job.refresh();

		TSLValidationModel czech = repository.getByCountry("CZ");
		assertNotNull(czech);

		TSLValidationModel eu = repository.getByCountry("EU");
		assertNotNull(eu);
		TSLParserResult parseResultEU = eu.getParseResult();
		assertNotNull(parseResultEU);
		TSLValidationResult validationResultEU = eu.getValidationResult();
		assertNotNull(validationResultEU);
		assertTrue(eu.isLotl());
		assertFalse(validationResultEU.isValid());
	}
	
	@Test
	public void missingPivotTest() throws IOException {
		repository.clearRepository();
		
		HashMap<String, byte[]> localUrlMap = new HashMap<String, byte[]>();
		localUrlMap.putAll(urlMap);
		localUrlMap.put(LOTL_URL, Files.readAllBytes(Paths.get("src/test/resources/lotlCache/tl_pivot_247_mp_missing-pivot.xml")));
		job.setDataLoader(new MemoryDataLoader(localUrlMap));
		
		job.refresh();

		TSLValidationModel czech = repository.getByCountry("CZ");
		assertNotNull(czech);

		TSLValidationModel eu = repository.getByCountry("EU");
		assertNotNull(eu);
		TSLParserResult parseResultEU = eu.getParseResult();
		assertNotNull(parseResultEU);
		TSLValidationResult validationResultEU = eu.getValidationResult();
		assertNotNull(validationResultEU);
		assertTrue(eu.isLotl());
		assertFalse(validationResultEU.isValid()); // TODO: check the expected behavior
	}
	
	@Test
	public void pivotNoSigTest() throws IOException {
		repository.clearRepository();
		
		HashMap<String, byte[]> localUrlMap = new HashMap<String, byte[]>();
		localUrlMap.putAll(urlMap);
		localUrlMap.put(LOTL_URL, Files.readAllBytes(Paths.get("src/test/resources/lotlCache/tl_pivot_247_mp_no-sig.xml")));
		job.setDataLoader(new MemoryDataLoader(localUrlMap));
		
		job.refresh();

		TSLValidationModel czech = repository.getByCountry("CZ");
		assertNotNull(czech);

		TSLValidationModel eu = repository.getByCountry("EU");
		assertNotNull(eu);
		TSLParserResult parseResultEU = eu.getParseResult();
		assertNotNull(parseResultEU);
		TSLValidationResult validationResultEU = eu.getValidationResult();
		assertNotNull(validationResultEU);
		assertTrue(eu.isLotl());
		assertFalse(validationResultEU.isValid());
	}
	
	@Test
	public void pivotNotParsableTest() throws IOException {
		repository.clearRepository();
		
		HashMap<String, byte[]> localUrlMap = new HashMap<String, byte[]>();
		localUrlMap.putAll(urlMap);
		localUrlMap.put(LOTL_URL, Files.readAllBytes(Paths.get("src/test/resources/lotlCache/tl_pivot_247_mp_not-parsable.xml")));
		job.setDataLoader(new MemoryDataLoader(localUrlMap));
		
		job.refresh();

		TSLValidationModel czech = repository.getByCountry("CZ");
		assertNull(czech);

		TSLValidationModel eu = repository.getByCountry("EU");
		assertNotNull(eu);
		TSLParserResult parseResultEU = eu.getParseResult();
		assertNull(parseResultEU);
		TSLValidationResult validationResultEU = eu.getValidationResult();
		assertFalse(eu.isLotl()); // TODO: the expected behavior ????
		assertNull(validationResultEU);
	}
	
	@Test
	public void pivotUtf8WithBomTest() throws IOException {
		repository.clearRepository();
		
		HashMap<String, byte[]> localUrlMap = new HashMap<String, byte[]>();
		localUrlMap.putAll(urlMap);
		localUrlMap.put(LOTL_URL, Files.readAllBytes(Paths.get("src/test/resources/lotlCache/tl_pivot_247_mp_with-bom.xml")));
		job.setDataLoader(new MemoryDataLoader(localUrlMap));
		
		job.refresh();

		TSLValidationModel czech = repository.getByCountry("CZ");
		assertNotNull(czech);

		TSLValidationModel eu = repository.getByCountry("EU");
		assertNotNull(eu);
		TSLParserResult parseResultEU = eu.getParseResult();
		assertNotNull(parseResultEU);
		TSLValidationResult validationResultEU = eu.getValidationResult();
		assertNotNull(validationResultEU);
		assertTrue(eu.isLotl());
		assertTrue(validationResultEU.isValid());
	}
	
	@Test
	public void pivotWithSpaces() throws IOException {
		repository.clearRepository();
		
		HashMap<String, byte[]> localUrlMap = new HashMap<String, byte[]>();
		localUrlMap.putAll(urlMap);
		localUrlMap.put(LOTL_URL, Files.readAllBytes(Paths.get("src/test/resources/lotlCache/tl_pivot_247_mp_with-spaces.xml")));
		job.setDataLoader(new MemoryDataLoader(localUrlMap));
		
		job.refresh();

		TSLValidationModel czech = repository.getByCountry("CZ");
		assertNotNull(czech);

		TSLValidationModel eu = repository.getByCountry("EU");
		assertNotNull(eu);
		TSLParserResult parseResultEU = eu.getParseResult();
		assertNotNull(parseResultEU);
		TSLValidationResult validationResultEU = eu.getValidationResult();
		assertNotNull(validationResultEU);
		assertTrue(eu.isLotl());
		assertTrue(validationResultEU.isValid());
	}

	@Test
	public void wrongKeystore() throws IOException {
		repository.clearRepository();
		
		job.setOjContentKeyStore(new KeyStoreCertificateSource(new File("src/test/resources/keystore_corrupted.p12"), "PKCS12", "dss-password"));
		job.refresh();

		TSLValidationModel czech = repository.getByCountry("CZ");
		assertNotNull(czech);
		TSLParserResult parseResultCZ = czech.getParseResult();
		assertNotNull(parseResultCZ);
		TSLValidationResult validationResultCZ = czech.getValidationResult();
		assertNotNull(validationResultCZ);
		assertTrue(validationResultCZ.isValid());

		TSLValidationModel eu = repository.getByCountry("EU");
		assertNotNull(eu);
		TSLParserResult parseResultEU = eu.getParseResult();
		assertNotNull(parseResultEU);
		TSLValidationResult validationResultEU = eu.getValidationResult();
		assertNotNull(validationResultEU);
		assertTrue(eu.isLotl());
		assertFalse(validationResultEU.isValid());
		// TODO: must be not valid ????
		
	}

}
