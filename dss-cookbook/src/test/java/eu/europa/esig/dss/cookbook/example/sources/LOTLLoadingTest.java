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
import java.util.HashMap;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.service.http.commons.FileCacheDataLoader;
import eu.europa.esig.dss.spi.client.http.MemoryDataLoader;
import eu.europa.esig.dss.spi.tsl.TrustedListsCertificateSource;
import eu.europa.esig.dss.spi.x509.CommonCertificateSource;
import eu.europa.esig.dss.spi.x509.KeyStoreCertificateSource;
import eu.europa.esig.dss.tsl.job.TLValidationJob;
import eu.europa.esig.dss.tsl.source.LOTLSource;
import eu.europa.esig.dss.tsl.source.TLSource;

public class LOTLLoadingTest {

	@Test
	public void loadLOTL() throws IOException {

		// tag::demo[]

		TrustedListsCertificateSource certificateSource = new TrustedListsCertificateSource();

		// The keystore contains certificates referenced in the Official Journal Link (OJ URL)
		KeyStoreCertificateSource keyStoreCertificateSource = new KeyStoreCertificateSource(new File("src/main/resources/keystore.p12"), "PKCS12",
				"dss-password");
		
		LOTLSource lotlSource = new LOTLSource();
		lotlSource.setUrl("https://ec.europa.eu/tools/lotl/eu-lotl.xml");
		lotlSource.setCertificateSource(keyStoreCertificateSource);
		lotlSource.setPivotSupport(true);
		
		FileCacheDataLoader offlineFileLoader = new FileCacheDataLoader(new MemoryDataLoader(new HashMap<String, byte[]>()));
		
		TLValidationJob validationJob = new TLValidationJob();
		validationJob.setTrustedListCertificateSource(certificateSource);
		validationJob.setOfflineDataLoader(offlineFileLoader);
		validationJob.setListOfTrustedListSources(lotlSource);
		validationJob.offlineRefresh();

		// end::demo[]

	}

	@Test
	public void additionalTL() {

		// tag::additionalTL[]

		TLValidationJob validationJob = new TLValidationJob();
		// ...

		// Configuration to load the peruvian trusted list.
		// DSS requires the URL and allowed signing certificates
		TLSource peru = new TLSource();
		peru.setUrl("https://iofe.indecopi.gob.pe/TSL/tsl-pe.xml");
		peru.setCertificateSource(new CommonCertificateSource());

		validationJob.setTrustedListSources(peru);

		// end::additionalTL[]

	}

}
