package eu.europa.esig.dss.tsl.service;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.junit.Before;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.client.http.commons.CommonsDataLoader;
import eu.europa.esig.dss.tsl.TSLValidationModel;
import eu.europa.esig.dss.tsl.TrustedListsCertificateSource;
import eu.europa.esig.dss.x509.KeyStoreCertificateSource;

public class TSLValidationJobTest {

	private static final Logger logger = LoggerFactory.getLogger(TSLValidationJobTest.class);

	private static final String OJ_URL = "http://eur-lex.europa.eu/legal-content/EN/TXT/?uri=uriserv:OJ.C_.2016.233.01.0001.01.ENG";
	private static final String LOTL_URL = "https://ec.europa.eu/information_society/policy/esignature/trusted-list/tl-mp.xml";
	private static final String LOTL_ROOT_SCHEME_INFO_URI = "https://ec.europa.eu/information_society/policy/esignature/trusted-list/tl.html";
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
		job.setOjUrl(OJ_URL);
		job.setLotlUrl(LOTL_URL);
		job.setLotlRootSchemeInfoUri(LOTL_ROOT_SCHEME_INFO_URI);
		job.setLotlCode("EU");
		job.setOjContentKeyStore(dssKeyStore);
		job.setRepository(repository);

		job.refresh();

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
		job.setOjUrl(OJ_URL);
		job.setLotlUrl(LOTL_URL);
		job.setLotlRootSchemeInfoUri(LOTL_ROOT_SCHEME_INFO_URI);
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
		job.setOjUrl(OJ_URL);
		job.setLotlUrl(LOTL_URL);
		job.setLotlRootSchemeInfoUri(LOTL_ROOT_SCHEME_INFO_URI);
		job.setLotlCode("EU");
		job.setOjContentKeyStore(dssKeyStore);
		job.setRepository(repository);

		logger.info("***************** First load *****************");
		job.refresh();

		logger.info("***************** Second load *****************");
		job.refresh();
	}
}
