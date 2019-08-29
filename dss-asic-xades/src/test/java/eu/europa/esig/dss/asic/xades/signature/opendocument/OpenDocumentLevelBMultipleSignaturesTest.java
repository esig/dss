package eu.europa.esig.dss.asic.xades.signature.opendocument;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.File;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.List;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

import eu.europa.esig.dss.asic.common.ASiCExtractResult;
import eu.europa.esig.dss.asic.common.AbstractASiCContainerExtractor;
import eu.europa.esig.dss.asic.xades.ASiCWithXAdESContainerExtractor;
import eu.europa.esig.dss.asic.xades.ASiCWithXAdESSignatureParameters;
import eu.europa.esig.dss.asic.xades.signature.ASiCWithXAdESService;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.MimeType;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.test.signature.PKIFactoryAccess;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;

@RunWith(Parameterized.class)
public class OpenDocumentLevelBMultipleSignaturesTest extends PKIFactoryAccess {

	private DSSDocument fileToTest;
	private DocumentSignatureService<ASiCWithXAdESSignatureParameters> service;
	private ASiCWithXAdESSignatureParameters signatureParameters;
	
	@Parameters(name = "Validation {index} : {0}")
	public static Collection<Object[]> data() {
		File folder = new File("src/test/resources/opendocument");
		Collection<File> listFiles = Utils.listFiles(folder,
				new String[] { "odt", "ods", "odp", "odg" }, true);
		Collection<Object[]> dataToRun = new ArrayList<Object[]>();
		for (File file : listFiles) {
			dataToRun.add(new Object[] { file });
		}
		return dataToRun;
	}
	
	public OpenDocumentLevelBMultipleSignaturesTest(File fileToTest) {
		this.fileToTest = new FileDocument(fileToTest);
	}
	
	@Before
	public void init() throws Exception {
		signatureParameters = new ASiCWithXAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(new Date());
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
		signatureParameters.aSiC().setContainerType(ASiCContainerType.ASiC_E);

		service = new ASiCWithXAdESService(getCompleteCertificateVerifier());
		service.setTspSource(getGoodTsa());
	}
	
	@Test
	public void test() throws Exception {
		doubleSignature(fileToTest);
	}
	
	public void doubleSignature(DSSDocument originalDocument) throws IOException {

		DSSDocument signedDocument = getSignedDocument(originalDocument);
		DSSDocument resignedDocument = getSignedDocument(signedDocument);
		
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(resignedDocument);
		validator.setCertificateVerifier(getCompleteCertificateVerifier());

		Reports reports = validator.validateDocument();
		
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		List<String> signatureIdList = diagnosticData.getSignatureIdList();
		assertEquals(2, signatureIdList.size());
		for (String sigId : signatureIdList) {
			assertTrue(diagnosticData.isBLevelTechnicallyValid(sigId));
			assertNotEquals(Indication.FAILED, reports.getSimpleReport().getIndication(sigId));
		}

		AbstractASiCContainerExtractor extractor = new ASiCWithXAdESContainerExtractor(resignedDocument);
		ASiCExtractResult result = extractor.extract();

		assertEquals(0, result.getUnsupportedDocuments().size());

		List<DSSDocument> signatureDocuments = result.getSignatureDocuments();
		assertEquals(1, signatureDocuments.size());
		String signatureFilename = signatureDocuments.get(0).getName();
		assertEquals("META-INF/documentsignatures.xml", signatureFilename);

		List<DSSDocument> manifestDocuments = result.getManifestDocuments();
		assertEquals(1, manifestDocuments.size());
		assertEquals("META-INF/manifest.xml", manifestDocuments.get(0).getName());

		List<DSSDocument> signedDocuments = result.getSignedDocuments();
		assertTrue(signedDocuments.size() > 4);

		DSSDocument mimeTypeDocument = result.getMimeTypeDocument();

		byte[] mimeTypeContent = DSSUtils.toByteArray(mimeTypeDocument);
		try {
			assertEquals(getMimeType().getMimeTypeString(), new String(mimeTypeContent, "UTF-8"));
		} catch (UnsupportedEncodingException e) {
			fail(e.getMessage());
		}

	}
	
	private DSSDocument getSignedDocument(DSSDocument originalDocument) {
		DSSDocument documentToSign = originalDocument;
		
		ASiCWithXAdESSignatureParameters signatureParameters = new ASiCWithXAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(new Date());
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
		signatureParameters.aSiC().setContainerType(ASiCContainerType.ASiC_E);

		ASiCWithXAdESService service = new ASiCWithXAdESService(getCompleteCertificateVerifier());
		
		ToBeSigned dataToSign = service.getDataToSign(documentToSign, signatureParameters);
		SignatureValue signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
		DSSDocument signedDocument = service.signDocument(documentToSign, signatureParameters, signatureValue);
		
		return signedDocument;
	}
	
	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}
	
	private MimeType getMimeType() {
		return fileToTest.getMimeType();
	}
}
