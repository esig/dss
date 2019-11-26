package eu.europa.esig.dss.asic.cades.signature.asice;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.util.ArrayList;
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
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.MimeType;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.test.signature.PKIFactoryAccess;
import eu.europa.esig.dss.validation.ManifestEntry;
import eu.europa.esig.dss.validation.ManifestFile;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;

public class ASiCECAdESSignLTALevelTest extends PKIFactoryAccess {
	
	@Test
	public void test() throws IOException {
		
		List<DSSDocument> documentsToSign = new ArrayList<DSSDocument>();
		documentsToSign.add(new InMemoryDocument("Hello World !".getBytes(), "test.text", MimeType.TEXT));
		documentsToSign.add(new InMemoryDocument("Bye World !".getBytes(), "test2.text", MimeType.TEXT));

		ASiCWithCAdESSignatureParameters signatureParameters = new ASiCWithCAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(new Date());
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_LTA);
		signatureParameters.aSiC().setContainerType(ASiCContainerType.ASiC_E);

		ASiCWithCAdESService service = new ASiCWithCAdESService(getCompleteCertificateVerifier());
		service.setTspSource(getGoodTsa());

		ToBeSigned dataToSign = service.getDataToSign(documentsToSign, signatureParameters);
		SignatureValue signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
		DSSDocument signedDocument = service.signDocument(documentsToSign, signatureParameters, signatureValue);
		
		DiagnosticData diagnosticData = validateDocument(signedDocument);
		
		assertEquals(1, diagnosticData.getSignatures().size());
		assertEquals(2, diagnosticData.getTimestampList().size());
		
		assertArchiveTimestampFound(diagnosticData);
		validateSignatures(diagnosticData.getSignatures());
		

		signatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_LTA);

		dataToSign = service.getDataToSign(signedDocument, signatureParameters);
		signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
		DSSDocument doubleSignedDocument = service.signDocument(signedDocument, signatureParameters, signatureValue);
		// doubleSignedDocument.save("target/doubleSignedDocument.asice");

		diagnosticData = validateDocument(doubleSignedDocument);
		
		assertEquals(2, diagnosticData.getSignatures().size());
		assertEquals(4, diagnosticData.getTimestampList().size());
		
		assertArchiveTimestampFound(diagnosticData);
		validateSignatures(diagnosticData.getSignatures());
		
		
		AbstractASiCContainerExtractor extractor = new ASiCWithCAdESContainerExtractor(doubleSignedDocument);
        ASiCExtractResult result = extractor.extract();
        
        assertEquals(11, result.getAllDocuments().size());
        assertEquals(4, result.getAllManifestDocuments().size());
        assertEquals(2, result.getArchiveManifestDocuments().size());
        assertEquals(0, result.getContainerDocuments().size());
        assertEquals(2, result.getManifestDocuments().size());
        assertNotNull(result.getMimeTypeDocument());
        assertEquals(2, result.getSignedDocuments().size());
        assertNotNull(result.getRootContainer());
        assertEquals(2, result.getSignatureDocuments().size());
        assertEquals(2, result.getTimestampDocuments().size());
        assertEquals(0, result.getUnsupportedDocuments().size());
        
        for (DSSDocument archiveManifest : result.getArchiveManifestDocuments()) {
        	if ("META-INF/ASiCArchiveManifest.xml".equals(archiveManifest.getName())) {
        		ManifestFile manifestFile = ASiCEWithCAdESManifestParser.getManifestFile(archiveManifest);
        		assertEquals(7, manifestFile.getEntries().size());
        		ManifestEntry rootFile = manifestFile.getRootFile();
        		assertNotNull(rootFile);
        		ManifestFile rootManifestFile = getManifestFileByName(rootFile.getFileName(), result.getArchiveManifestDocuments());
        		assertNull(rootManifestFile.getRootFile());
        	}
        }
		
	}
	
	private DiagnosticData validateDocument(DSSDocument document) {
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(document);
		validator.setCertificateVerifier(getOfflineCertificateVerifier());

		Reports reports = validator.validateDocument();
		return reports.getDiagnosticData();
	}
	
	private void assertArchiveTimestampFound(DiagnosticData diagnosticData) {
		boolean archiveTimestampFound = false;
		for (TimestampWrapper timestamp : diagnosticData.getTimestampList()) {
			if (timestamp.getType().isArchivalTimestamp()) {
				archiveTimestampFound = true;
			}
		}
		assertTrue(archiveTimestampFound);
	}
	
	private void validateSignatures(List<SignatureWrapper> signatures) {
		for (SignatureWrapper signature : signatures) {
			assertTrue(signature.isBLevelTechnicallyValid());
			assertTrue(signature.isSignatureValid());
			assertTrue(signature.isSignatureIntact());
			for (XmlDigestMatcher digestMatcher : signature.getDigestMatchers()) {
				assertTrue(digestMatcher.isDataFound());
				assertTrue(digestMatcher.isDataIntact());
			}
		}
	}
	
	private ManifestFile getManifestFileByName(String manifestName, List<DSSDocument> manifestList) {
		for (DSSDocument manifest : manifestList) {
			if (manifestName.equals(manifest.getName())) {
				return ASiCEWithCAdESManifestParser.getManifestFile(manifest);
			}
		}
		return null;
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}
