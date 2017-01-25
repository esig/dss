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
package eu.europa.esig.dss.cookbook.example.validate;

import static org.junit.Assert.assertNotNull;

import java.io.File;
import java.io.IOException;

import org.junit.Test;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.client.crl.OnlineCRLSource;
import eu.europa.esig.dss.client.http.commons.CommonsDataLoader;
import eu.europa.esig.dss.client.http.commons.FileCacheDataLoader;
import eu.europa.esig.dss.client.ocsp.OnlineOCSPSource;
import eu.europa.esig.dss.cookbook.example.CookbookTools;
import eu.europa.esig.dss.test.mock.MockServiceInfo;
import eu.europa.esig.dss.tsl.TrustedListsCertificateSource;
import eu.europa.esig.dss.tsl.service.TSLRepository;
import eu.europa.esig.dss.tsl.service.TSLValidationJob;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.DetailedReport;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.validation.reports.SimpleReport;
import eu.europa.esig.dss.x509.CertificateToken;
import eu.europa.esig.dss.x509.KeyStoreCertificateSource;

/**
 * How to validate a XAdES-BASELINE-LT enveloped signature with online sources.
 */
public class ValidateXmlXadesLTWithOnlineSourcesTest extends CookbookTools {

	@Test
	public void validateXAdESBaselineLTWithOnlineSources() throws IOException {

		// tag::demo[]

		// To be able to validate our fake signature, we must define one of the certificates in the chain as trusted
		// anchor.
		// If you have a real signature for which it is possible to build the chain till the TSL then just skip this
		// point.
		preparePKCS12TokenAndKey();
		final CertificateToken[] certificateChain = privateKey.getCertificateChain();
		final CertificateToken trustedCertificate = certificateChain[0];

		// Already signed document
		DSSDocument document = new FileDocument(new File("src/test/resources/signedXmlXadesLT.xml"));

		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(document);

		CommonsDataLoader commonsDataLoader = new CommonsDataLoader();

		CommonCertificateVerifier verifier = new CommonCertificateVerifier();
		OnlineCRLSource crlSource = new OnlineCRLSource();
		crlSource.setDataLoader(commonsDataLoader);
		verifier.setCrlSource(crlSource);

		OnlineOCSPSource ocspSource = new OnlineOCSPSource();
		// The default OCSPDataLoader is created. You can also create your own HttpDataLoader.
		verifier.setOcspSource(ocspSource);

		// SEE NOTE 1
		FileCacheDataLoader fileCacheDataLoader = new FileCacheDataLoader();
		File cacheFolder = new File("/temp");
		fileCacheDataLoader.setFileCacheDirectory(cacheFolder);

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

		certificateSource.addCertificate(trustedCertificate, new MockServiceInfo());
		verifier.setTrustedCertSource(certificateSource);

		verifier.setDataLoader(fileCacheDataLoader);

		validator.setCertificateVerifier(verifier);

		Reports reports = validator.validateDocument();
		SimpleReport simpleReport = reports.getSimpleReport();
		DetailedReport detailedReport = reports.getDetailedReport();

		// end::demo[]

		assertNotNull(reports);
		assertNotNull(simpleReport);
		assertNotNull(detailedReport);
	}
}