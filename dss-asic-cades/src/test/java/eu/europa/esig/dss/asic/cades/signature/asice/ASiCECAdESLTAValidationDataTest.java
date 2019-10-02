package eu.europa.esig.dss.asic.cades.signature.asice;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.List;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.asic.cades.ASiCWithCAdESContainerExtractor;
import eu.europa.esig.dss.asic.cades.ASiCWithCAdESSignatureParameters;
import eu.europa.esig.dss.asic.cades.signature.ASiCWithCAdESService;
import eu.europa.esig.dss.asic.cades.validation.ASiCEWithCAdESManifestParser;
import eu.europa.esig.dss.asic.common.ASiCExtractResult;
import eu.europa.esig.dss.asic.common.AbstractASiCContainerExtractor;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.MimeType;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.service.crl.OnlineCRLSource;
import eu.europa.esig.dss.service.http.commons.CommonsDataLoader;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.test.signature.PKIFactoryAccess;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.ManifestEntry;
import eu.europa.esig.dss.validation.ManifestFile;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;

// see DSS-1805
public class ASiCECAdESLTAValidationDataTest extends PKIFactoryAccess {
	
	private static Date currentDate = new Date();
	
	@Test
	public void test() throws Exception {
		List<DSSDocument> documentToSigns = new ArrayList<DSSDocument>();
		documentToSigns.add(new InMemoryDocument("Hello World !".getBytes(), "test.text", MimeType.TEXT));
		documentToSigns.add(new InMemoryDocument("Bye World !".getBytes(), "test2.text", MimeType.TEXT));

		ASiCWithCAdESSignatureParameters signatureParameters = new ASiCWithCAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(new Date());
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_LTA);
		signatureParameters.aSiC().setContainerType(ASiCContainerType.ASiC_E);

		CertificateVerifier completeCertificateVerifier = getCompleteCertificateVerifier();
		OnlineCRLSource onlineCRLSource = new OnlineCRLSource();
		MockCRLDataLoader mockCRLDataLoader = new MockCRLDataLoader();
		onlineCRLSource.setDataLoader(mockCRLDataLoader);
		completeCertificateVerifier.setCrlSource(onlineCRLSource);
		completeCertificateVerifier.setOcspSource(null);
		ASiCWithCAdESService service = new ASiCWithCAdESService(completeCertificateVerifier);
		service.setTspSource(getGoodTsa());

		ToBeSigned dataToSign = service.getDataToSign(documentToSigns, signatureParameters);
		SignatureValue signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
		DSSDocument signedDocument = service.signDocument(documentToSigns, signatureParameters, signatureValue);
		// signedDocument.save("target/signed.asice");
		
		AbstractASiCContainerExtractor extractor = new ASiCWithCAdESContainerExtractor(signedDocument);
		ASiCExtractResult result = extractor.extract();
		
		List<DSSDocument> signatures = result.getSignatureDocuments();
		assertEquals(1, signatures.size());
		String signatureDigest = signatures.get(0).getDigest(DigestAlgorithm.SHA256);

		Calendar calendar = Calendar.getInstance();
		calendar.setTime(currentDate);
		calendar.add(Calendar.MONTH, 6);
		currentDate = calendar.getTime();
		service.setTspSource(getGoodTsaByTime(currentDate));
		
		ASiCWithCAdESSignatureParameters extendParameters = new ASiCWithCAdESSignatureParameters();
		extendParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_LTA);
		extendParameters.aSiC().setContainerType(ASiCContainerType.ASiC_E);
		DSSDocument extendedDocument = service.extendDocument(signedDocument, extendParameters);
		// extendedDocument.save("target/extendedDocument.asice");
		
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(extendedDocument);
		validator.setCertificateVerifier(getOfflineCertificateVerifier());
		
		Reports reports = validator.validateDocument();
		// reports.print();
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertTrue(signature.isBLevelTechnicallyValid());
		assertTrue(signature.isSignatureIntact());
		assertTrue(signature.isSignatureValid());
		for (XmlDigestMatcher digestMatcher : signature.getDigestMatchers()) {
			assertTrue(digestMatcher.isDataFound());
			assertTrue(digestMatcher.isDataIntact());
		}
		
		List<TimestampWrapper> timestampList = diagnosticData.getTimestampList();
		for (TimestampWrapper timestamp : timestampList) {
			assertTrue(timestamp.isSignatureIntact());
			assertTrue(timestamp.isSignatureValid());
			assertTrue(timestamp.isMessageImprintDataFound());
			assertTrue(timestamp.isMessageImprintDataIntact());
		}
		
		extractor = new ASiCWithCAdESContainerExtractor(extendedDocument);
		result = extractor.extract();
		
		List<DSSDocument> archiveManifests = result.getArchiveManifestDocuments();
		assertEquals(2, archiveManifests.size());
		
		ManifestFile archiveManifestFile1 = ASiCEWithCAdESManifestParser.getManifestFile(archiveManifests.get(0));
		ManifestFile archiveManifestFile2 = ASiCEWithCAdESManifestParser.getManifestFile(archiveManifests.get(1));

		assertNotEquals(archiveManifestFile1.getFilename(), archiveManifestFile2.getFilename());
		
		Digest firstArchManifestSigDigest = getSignatureDigest(archiveManifestFile1);
		Digest secondArchManifestSigDigest = getSignatureDigest(archiveManifestFile2);
		
		assertEquals(signatureDigest, Utils.toBase64(firstArchManifestSigDigest.getValue()));
		assertEquals(signatureDigest, Utils.toBase64(secondArchManifestSigDigest.getValue()));
		
	}
	
	private Digest getSignatureDigest(ManifestFile archiveManifestFile) {
		Digest digest = null;
		for (ManifestEntry entry : archiveManifestFile.getEntries()) {
			if ("META-INF/signature001.p7s".equals(entry.getFileName())) {
				digest = entry.getDigest();
				break;
			}
		}
		assertNotNull(digest);
		return digest;
	}
	
	@SuppressWarnings("serial")
	private class MockCRLDataLoader extends CommonsDataLoader {
		
		private static final String DEFAULT_DATE_FORMAT = "yyyy-MM-dd-HH-mm";
		
		@Override
		public DataAndUrl get(List<String> urlStrings) {
			if (Utils.isCollectionNotEmpty(urlStrings)) {
				for (String url : urlStrings) {
					if (url.contains("/pki-factory/crl/good-ca.crl")) {
						Calendar calendar = Calendar.getInstance();
						calendar.setTime(currentDate);
						calendar.add(Calendar.MINUTE, -1);
						String requestDate = DSSUtils.formatDateWithCustomFormat(calendar.getTime(), DEFAULT_DATE_FORMAT);
						String newUrl = url.replace("/pki-factory/crl/good-ca.crl", "/pki-factory/crl/" + requestDate + "/true/good-ca.crl");
						return new DataAndUrl(super.get(newUrl), url);
					}
				}
			}
			return super.get(urlStrings);
		}
		
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER_WITH_CRL_AND_OCSP;
	}

}
