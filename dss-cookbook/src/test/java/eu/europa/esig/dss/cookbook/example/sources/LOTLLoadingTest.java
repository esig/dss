package eu.europa.esig.dss.cookbook.example.sources;

import java.io.File;

import org.junit.Test;

import eu.europa.esig.dss.client.http.commons.CommonsDataLoader;
import eu.europa.esig.dss.tsl.TrustedListsCertificateSource;
import eu.europa.esig.dss.tsl.service.TSLRepository;
import eu.europa.esig.dss.tsl.service.TSLValidationJob;
import eu.europa.esig.dss.x509.KeyStoreCertificateSource;

public class LOTLLoadingTest {

	@Test
	public void loadLOTL() {

		// tag::demo[]

		// The keystore contains certificates extracted from the OJ
		KeyStoreCertificateSource keyStoreCertificateSource = new KeyStoreCertificateSource(new File("src/main/resources/keystore.p12"), "PKCS12",
				"dss-password");

		TrustedListsCertificateSource certificateSource = new TrustedListsCertificateSource();

		TSLRepository tslRepository = new TSLRepository();
		tslRepository.setTrustedListsCertificateSource(certificateSource);

		TSLValidationJob job = new TSLValidationJob();
		job.setDataLoader(new CommonsDataLoader());
		job.setDssKeyStore(keyStoreCertificateSource);
		job.setLotlUrl("https://ec.europa.eu/information_society/policy/esignature/trusted-list/tl-mp.xml");
		job.setOjUrl("http://eur-lex.europa.eu/legal-content/EN/TXT/?uri=uriserv:OJ.C_.2016.233.01.0001.01.ENG");
		job.setLotlCode("EU");
		job.setRepository(tslRepository);

		job.refresh();

		// end::demo[]

	}
}
