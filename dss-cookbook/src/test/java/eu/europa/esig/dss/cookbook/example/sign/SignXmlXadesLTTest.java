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
package eu.europa.esig.dss.cookbook.example.sign;

import eu.europa.esig.dss.cookbook.example.CookbookTools;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.service.crl.OnlineCRLSource;
import eu.europa.esig.dss.service.http.commons.CommonsDataLoader;
import eu.europa.esig.dss.service.http.commons.FileCacheDataLoader;
import eu.europa.esig.dss.service.http.commons.OCSPDataLoader;
import eu.europa.esig.dss.service.ocsp.OnlineOCSPSource;
import eu.europa.esig.dss.spi.tsl.TrustedListsCertificateSource;
import eu.europa.esig.dss.spi.x509.KeyStoreCertificateSource;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.SignatureTokenConnection;
import eu.europa.esig.dss.tsl.cache.CacheCleaner;
import eu.europa.esig.dss.tsl.job.TLValidationJob;
import eu.europa.esig.dss.tsl.source.LOTLSource;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.signature.XAdESService;
import org.junit.jupiter.api.Test;

import java.io.File;

/**
 * How to sign with XAdES-BASELINE-LT
 */
class SignXmlXadesLTTest extends CookbookTools {

	@Test
	void signXAdESBaselineLT() throws Exception {

		// GET document to be signed -
		// Return DSSDocument toSignDocument
		prepareXmlDoc();

		// Get a token connection based on a pkcs12 file commonly used to store private
		// keys with accompanying public key certificates, protected with a password-based
		// symmetric key -
		// Return AbstractSignatureTokenConnection signingToken
		// and it's first private key entry from the PKCS12 store
		// Return DSSPrivateKeyEntry privateKey *****
		try (SignatureTokenConnection signingToken = getUserPkcs12Token()) {

			DSSPrivateKeyEntry privateKey = signingToken.getKeys().get(0);

			// tag::demo[]
			// import eu.europa.esig.dss.enumerations.DigestAlgorithm;
			// import eu.europa.esig.dss.enumerations.SignatureLevel;
			// import eu.europa.esig.dss.enumerations.SignaturePackaging;
			// import eu.europa.esig.dss.model.DSSDocument;
			// import eu.europa.esig.dss.model.SignatureValue;
			// import eu.europa.esig.dss.model.ToBeSigned;
			// import eu.europa.esig.dss.service.crl.OnlineCRLSource;
			// import eu.europa.esig.dss.service.http.commons.CommonsDataLoader;
			// import eu.europa.esig.dss.service.http.commons.FileCacheDataLoader;
			// import eu.europa.esig.dss.service.http.commons.OCSPDataLoader;
			// import eu.europa.esig.dss.service.ocsp.OnlineOCSPSource;
			// import eu.europa.esig.dss.spi.tsl.TrustedListsCertificateSource;
			// import eu.europa.esig.dss.spi.x509.KeyStoreCertificateSource;
			// import eu.europa.esig.dss.tsl.cache.CacheCleaner;
			// import eu.europa.esig.dss.tsl.job.TLValidationJob;
			// import eu.europa.esig.dss.tsl.source.LOTLSource;
			// import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
			// import eu.europa.esig.dss.xades.XAdESSignatureParameters;
			// import eu.europa.esig.dss.xades.signature.XAdESService;
			// import java.io.File;

			// Preparing parameters for the XAdES signature
			XAdESSignatureParameters parameters = new XAdESSignatureParameters();
			// We choose the level of the signature (-B, -T, -LT, -LTA).
			parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_LT);
			// We choose the type of the signature packaging (ENVELOPED, ENVELOPING, DETACHED).
			parameters.setSignaturePackaging(SignaturePackaging.ENVELOPED);
			// We set the digest algorithm to use with the signature algorithm. You must use the
			// same parameter when you invoke the method sign on the token. The default value is SHA256
			parameters.setDigestAlgorithm(DigestAlgorithm.SHA256);

			// We set the signing certificate
			parameters.setSigningCertificate(privateKey.getCertificate());
			// We set the certificate chain
			parameters.setCertificateChain(privateKey.getCertificateChain());

			CommonsDataLoader commonsDataLoader = new CommonsDataLoader();
			OCSPDataLoader ocspDataLoader = new OCSPDataLoader();

			KeyStoreCertificateSource keyStoreCertificateSource = new KeyStoreCertificateSource(
					new File("src/main/resources/keystore.p12"), "PKCS12", getPassword());
			
			LOTLSource lotlSource = new LOTLSource();
			lotlSource.setUrl("https://ec.europa.eu/tools/lotl/eu-lotl.xml");
			lotlSource.setCertificateSource(keyStoreCertificateSource);
			lotlSource.setPivotSupport(true);

			TrustedListsCertificateSource tslCertificateSource = new TrustedListsCertificateSource();
			
			FileCacheDataLoader onlineFileLoader = new FileCacheDataLoader(commonsDataLoader);
			
			CacheCleaner cacheCleaner = new CacheCleaner();
			cacheCleaner.setCleanFileSystem(true);
			cacheCleaner.setDSSFileLoader(onlineFileLoader);
			
			TLValidationJob validationJob = new TLValidationJob();
			validationJob.setTrustedListCertificateSource(tslCertificateSource);
			validationJob.setOnlineDataLoader(onlineFileLoader);
			validationJob.setCacheCleaner(cacheCleaner);
			validationJob.setListOfTrustedListSources(lotlSource);
			validationJob.onlineRefresh();

			// tag::certificate-verifier[]

			// Create common certificate verifier
			CommonCertificateVerifier commonCertificateVerifier = new CommonCertificateVerifier();

			// Provide trust anchors
			commonCertificateVerifier.setTrustedCertSources(tslCertificateSource);

			// Instantiate CRL source
			OnlineCRLSource onlineCRLSource = new OnlineCRLSource();
			onlineCRLSource.setDataLoader(commonsDataLoader);
			commonCertificateVerifier.setCrlSource(onlineCRLSource);

			// Instantiate OCSP source
			OnlineOCSPSource onlineOCSPSource = new OnlineOCSPSource();
			onlineOCSPSource.setDataLoader(ocspDataLoader);
			commonCertificateVerifier.setOcspSource(onlineOCSPSource);

			// For test purpose (not recommended for use in production)
			// Will request unknown OCSP responder / download untrusted CRL
			commonCertificateVerifier.setCheckRevocationForUntrustedChains(true);

			// Create XAdES service for signature
			XAdESService service = new XAdESService(commonCertificateVerifier);
			// end::certificate-verifier[]
			service.setTspSource(getOnlineTSPSource());

			// Get the SignedInfo XML segment that need to be signed.
			ToBeSigned dataToSign = service.getDataToSign(toSignDocument, parameters);

			// This function obtains the signature value for signed information using the
			// private key and specified algorithm
			SignatureValue signatureValue = signingToken.sign(dataToSign, parameters.getDigestAlgorithm(), privateKey);

			// We invoke the service to sign the document with the signature value obtained in
			// the previous step.
			DSSDocument signedDocument = service.signDocument(toSignDocument, parameters, signatureValue);

			// end::demo[]

			testFinalDocument(signedDocument);
		}
	}

	private char[] getPassword() {
		return "dss-password".toCharArray();
	}

}
