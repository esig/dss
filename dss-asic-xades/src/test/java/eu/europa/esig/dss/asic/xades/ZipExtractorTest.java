package eu.europa.esig.dss.asic.xades;

import static org.hamcrest.CoreMatchers.hasItems;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;

import java.io.File;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.asic.common.ASiCExtractResult;
import eu.europa.esig.dss.asic.common.ASiCUtils;
import eu.europa.esig.dss.asic.xades.signature.ASiCWithXAdESService;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.MimeType;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.spi.x509.tsp.TSPSource;
import eu.europa.esig.dss.test.signature.PKIFactoryAccess;

public class ZipExtractorTest extends PKIFactoryAccess{
	
	private DSSDocument openDocument;
	private DSSDocument zipArchive;
	
	
	@BeforeEach
	public void init() throws Exception {
		openDocument = new FileDocument(new File("src/test/resources/signable/open-document.odt"));
		zipArchive = new FileDocument(new File("src/test/resources/signable/test.zip"));
	}
	
	@Test
	public void extractUnsignedOpenDocument() {
		ASiCWithXAdESContainerExtractor extractor = new ASiCWithXAdESContainerExtractor(openDocument);
		ASiCExtractResult extract = extractor.extract();
		
		assertNotNull(extract);
		
		assertNotNull(extract.getManifestFiles());
		assertNotNull(extract.getManifestDocuments());
		assertEquals(1, extract.getManifestDocuments().size());

		assertNotNull(extract.getContainerDocuments());
		assertNotNull(extract.getMimeTypeDocument());
		assertNotNull(extract.getRootContainer());

		assertNotNull(extract.getSignatureDocuments());
		assertNotNull(extract.getSignedDocuments());
		assertEquals(12, extract.getSignedDocuments().size());
	}
	
	@Test
	public void extractUnsignedZip() {
		ASiCWithXAdESContainerExtractor extractor = new ASiCWithXAdESContainerExtractor(zipArchive);
		ASiCExtractResult extract = extractor.extract();
		
		assertNotNull(extract);
		
		assertNotNull(extract.getManifestFiles());
		assertNotNull(extract.getManifestDocuments());
		assertEquals(0, extract.getManifestDocuments().size());

		assertNotNull(extract.getContainerDocuments());
		assertEquals(null, extract.getMimeTypeDocument());
		assertNotNull(extract.getRootContainer());

		assertNotNull(extract.getSignatureDocuments());
		assertEquals(0, extract.getSignatureDocuments().size());
		assertNotNull(extract.getSignedDocuments());
		assertEquals(1, extract.getSignedDocuments().size());
	}
	
	@Test
	public void extractSignedZip() {
		DSSDocument document = signDocument(zipArchive);
		ASiCWithXAdESContainerExtractor extractor = new ASiCWithXAdESContainerExtractor(document);
		ASiCExtractResult extract = extractor.extract();
		
		assertNotNull(extract);
		
		assertNotNull(extract.getManifestFiles());
		assertNotNull(extract.getManifestDocuments());
		assertEquals(1, extract.getManifestDocuments().size());

		assertNotNull(extract.getContainerDocuments());
	
		assertNotNull(extract.getMimeTypeDocument());
		MimeType mimeType = ASiCUtils.getMimeType(extract.getMimeTypeDocument());
		assertEquals("application/vnd.etsi.asic-e+zip",  mimeType.getMimeTypeString());
		
		assertNotNull(extract.getRootContainer());
		
		assertNotNull(extract.getSignatureDocuments());
		assertEquals(1, extract.getSignatureDocuments().size());
		assertNotNull(extract.getSignedDocuments());
		assertEquals(1, extract.getSignedDocuments().size());
		
		assertEquals("test.zip", extract.getSignedDocuments().get(0).getName());		
	}
	
	@Test
	public void extractSignedOpenDocument() {
		DSSDocument document = signDocument(openDocument);
		ASiCWithXAdESContainerExtractor extractor = new ASiCWithXAdESContainerExtractor(document);
		ASiCExtractResult extract = extractor.extract();
		
		assertNotNull(extract);
		
		assertNotNull(extract.getManifestFiles());
		assertNotNull(extract.getManifestDocuments());
		assertEquals(1, extract.getManifestDocuments().size());

		assertNotNull(extract.getContainerDocuments());
	
		assertNotNull(extract.getMimeTypeDocument());
		MimeType mimeType = ASiCUtils.getMimeType(extract.getMimeTypeDocument());
		assertEquals("application/vnd.oasis.opendocument.text",  mimeType.getMimeTypeString());
		
		assertNotNull(extract.getRootContainer());
		
		assertNotNull(extract.getSignatureDocuments());
		assertEquals(1, extract.getSignatureDocuments().size());
		assertNotNull(extract.getSignedDocuments());
		assertEquals(12, extract.getSignedDocuments().size());
		
		checkDocuments(openDocument, document);
	}
	
	private DSSDocument signDocument(DSSDocument documentToSign) {
		
		ASiCWithXAdESSignatureParameters signatureParameters = new ASiCWithXAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(new Date());
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setSignedInfoCanonicalizationMethod("http://www.w3.org/TR/2001/REC-xml-c14n-20010315");
		signatureParameters.setSignedPropertiesCanonicalizationMethod("http://www.w3.org/TR/2001/REC-xml-c14n-20010315");
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
		signatureParameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
		signatureParameters.aSiC().setContainerType(ASiCContainerType.ASiC_E);

		ASiCWithXAdESService service = new ASiCWithXAdESService(getCompleteCertificateVerifier());
		service.setTspSource(getUsedTSPSourceAtSignatureTime());
		
		ToBeSigned dataToSign = service.getDataToSign(documentToSign, signatureParameters);
		SignatureValue signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
		DSSDocument signedDocument = service.signDocument(documentToSign, signatureParameters, signatureValue);
		
		return signedDocument;
	}
	
	private void checkDocuments(DSSDocument original, DSSDocument signed) {		
		ASiCWithXAdESContainerExtractor extractor = new ASiCWithXAdESContainerExtractor(original);
		ASiCExtractResult extractOriginal = extractor.extract();
		
		extractor = new ASiCWithXAdESContainerExtractor(signed);
		ASiCExtractResult extractSigned = extractor.extract();
		
		assertEquals(0, extractOriginal.getContainerDocuments().size());
		assertEquals(0, extractSigned.getContainerDocuments().size());
		
		assertEquals(0, extractOriginal.getSignatureDocuments().size());
		assertEquals(1, extractSigned.getSignatureDocuments().size());
		
		assertEquals(extractOriginal.getSignedDocuments().size(), extractSigned.getSignedDocuments().size());
		
		List<String> fileNames = getSignedFilesNames(extractSigned.getSignedDocuments());		
		List<String> fileDigests = getSignedFilesDigests(extractSigned.getSignedDocuments());

		for(DSSDocument doc : extractOriginal.getSignedDocuments()) {
			assertThat(fileNames, hasItems(doc.getName()));
			assertThat(fileDigests, hasItems(doc.getDigest(DigestAlgorithm.SHA256)));
		}	
	}
	
	private List<String> getSignedFilesNames(List<DSSDocument> files) {
		List<String> fileNames = new ArrayList<String>();
		for(DSSDocument doc: files) {
			fileNames.add(doc.getName());
		}
		return fileNames;
	}
	
	private List<String> getSignedFilesDigests(List<DSSDocument> files) {
		List<String> fileDigests = new ArrayList<String>();
		for(DSSDocument doc: files) {
			fileDigests.add(doc.getDigest(DigestAlgorithm.SHA256));
		}
		return fileDigests;
	}
	
	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}
	
	protected TSPSource getUsedTSPSourceAtSignatureTime() {
		return getGoodTsa();
	}

}
