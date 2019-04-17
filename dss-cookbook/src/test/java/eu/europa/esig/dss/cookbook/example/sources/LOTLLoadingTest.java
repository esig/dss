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
package eu.europa.esig.dss.cookbook.example.sources;

import java.io.File;
import java.io.IOException;
import java.util.Arrays;

import org.junit.Test;

import eu.europa.esig.dss.client.http.commons.CommonsDataLoader;
import eu.europa.esig.dss.tsl.OtherTrustedList;
import eu.europa.esig.dss.tsl.TrustedListsCertificateSource;
import eu.europa.esig.dss.tsl.service.TSLRepository;
import eu.europa.esig.dss.tsl.service.TSLValidationJob;
import eu.europa.esig.dss.x509.KeyStoreCertificateSource;

public class LOTLLoadingTest {

	@Test
	public void loadLOTL() throws IOException {

		// tag::demo[]

		TSLRepository tslRepository = new TSLRepository();

		TrustedListsCertificateSource certificateSource = new TrustedListsCertificateSource();
		tslRepository.setTrustedListsCertificateSource(certificateSource);

		TSLValidationJob job = new TSLValidationJob();
		job.setDataLoader(new CommonsDataLoader());
		job.setCheckLOTLSignature(true);
		job.setCheckTSLSignatures(true);
		job.setLotlUrl("https://ec.europa.eu/information_society/policy/esignature/trusted-list/tl-mp.xml");
		job.setLotlCode("EU");

		// This information is needed to be able to filter the LOTL pivots
		job.setLotlRootSchemeInfoUri("https://ec.europa.eu/information_society/policy/esignature/trusted-list/tl.html");

		// The keystore contains certificates referenced in the Official Journal Link (OJ URL)
		KeyStoreCertificateSource keyStoreCertificateSource = new KeyStoreCertificateSource(new File("src/main/resources/keystore.p12"), "PKCS12",
				"dss-password");
		job.setOjDomainName("eur-lex.europa.eu");
		job.setOjContentKeyStore(keyStoreCertificateSource);

		job.setRepository(tslRepository);

		job.refresh();

		// end::demo[]

	}

	public void additionalTL() {

		// tag::additionalTL[]

		TSLValidationJob job = new TSLValidationJob();
		// ...

		// Configuration to load the peruvian trusted list.
		// DSS requires the country code, the URL and allowed signing certificates
		OtherTrustedList peru = new OtherTrustedList();
		peru.setCountryCode("PE");
		peru.setUrl("https://iofe.indecopi.gob.pe/TSL/tsl-pe.xml");
		peru.setTrustStore(getTrustStore());

		job.setOtherTrustedLists(Arrays.asList(peru));

		// end::additionalTL[]

	}

	private KeyStoreCertificateSource getTrustStore() {
		return null;
	}

}
