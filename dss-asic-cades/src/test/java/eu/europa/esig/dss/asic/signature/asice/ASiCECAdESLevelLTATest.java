package eu.europa.esig.dss.asic.signature.asice;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.tsp.TimeStampToken;
import org.junit.Test;

import eu.europa.esig.dss.ASiCContainerType;
import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.MimeType;
import eu.europa.esig.dss.SignatureAlgorithm;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.SignatureValue;
import eu.europa.esig.dss.ToBeSigned;
import eu.europa.esig.dss.asic.ASiCExtractResult;
import eu.europa.esig.dss.asic.ASiCWithCAdESContainerExtractor;
import eu.europa.esig.dss.asic.ASiCWithCAdESSignatureParameters;
import eu.europa.esig.dss.asic.AbstractASiCContainerExtractor;
import eu.europa.esig.dss.asic.signature.ASiCWithCAdESService;
import eu.europa.esig.dss.test.TestUtils;
import eu.europa.esig.dss.test.gen.CertificateService;
import eu.europa.esig.dss.test.mock.MockPrivateKeyEntry;
import eu.europa.esig.dss.test.mock.MockTSPSource;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.TimestampToken;
import eu.europa.esig.dss.x509.CertificatePool;
import eu.europa.esig.dss.x509.TimestampType;

public class ASiCECAdESLevelLTATest {

	@Test
	public void test() throws Exception {
		List<DSSDocument> documentToSigns = new ArrayList<DSSDocument>();
		documentToSigns.add(new InMemoryDocument("Hello World !".getBytes(), "test.text", MimeType.TEXT));
		documentToSigns.add(new InMemoryDocument("Bye World !".getBytes(), "test2.text", MimeType.TEXT));

		CertificateService certificateService = new CertificateService();
		MockPrivateKeyEntry privateKeyEntry = certificateService.generateCertificateChain(SignatureAlgorithm.RSA_SHA256);

		ASiCWithCAdESSignatureParameters signatureParameters = new ASiCWithCAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(new Date());
		signatureParameters.setSigningCertificate(privateKeyEntry.getCertificate());
		signatureParameters.setCertificateChain(privateKeyEntry.getCertificateChain());
		signatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_LTA);
		signatureParameters.aSiC().setContainerType(ASiCContainerType.ASiC_E);

		CertificateVerifier certificateVerifier = new CommonCertificateVerifier();
		ASiCWithCAdESService service = new ASiCWithCAdESService(certificateVerifier);
		service.setTspSource(new MockTSPSource(certificateService.generateTspCertificate(SignatureAlgorithm.RSA_SHA1)));

		ToBeSigned dataToSign = service.getDataToSign(documentToSigns, signatureParameters);
		SignatureValue signatureValue = TestUtils.sign(SignatureAlgorithm.RSA_SHA256, privateKeyEntry, dataToSign);
		DSSDocument signedDocument = service.signDocument(documentToSigns, signatureParameters, signatureValue);

		AbstractASiCContainerExtractor extractor = new ASiCWithCAdESContainerExtractor(signedDocument);
		ASiCExtractResult result = extractor.extract();

		assertEquals(0, result.getUnsupportedDocuments().size());
		assertEquals(1, result.getArchiveManifestDocuments().size());
		assertEquals(1, result.getTimestampDocuments().size());
		assertEquals(1, result.getManifestDocuments().size());
		assertEquals(1, result.getSignatureDocuments().size());

		DSSDocument archiveManifest = result.getArchiveManifestDocuments().get(0);
		byte[] expectedTimestampedBinaries = DSSUtils.toByteArray(archiveManifest);

		DSSDocument timestampDoc = result.getTimestampDocuments().get(0);
		TimeStampToken timeStamp = new TimeStampToken(new CMSSignedData(timestampDoc.openStream()));
		TimestampToken token = new TimestampToken(timeStamp, TimestampType.ARCHIVE_TIMESTAMP, new CertificatePool());
		assertTrue(token.matchData(expectedTimestampedBinaries));
	}
}
