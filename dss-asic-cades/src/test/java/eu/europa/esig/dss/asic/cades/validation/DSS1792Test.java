package eu.europa.esig.dss.asic.cades.validation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.util.List;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.asic.cades.ASiCWithCAdESContainerExtractor;
import eu.europa.esig.dss.asic.common.ASiCExtractResult;
import eu.europa.esig.dss.asic.common.AbstractASiCContainerExtractor;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.test.signature.PKIFactoryAccess;
import eu.europa.esig.dss.validation.ManifestFile;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;

public class DSS1792Test extends PKIFactoryAccess {
	
	private static final DSSDocument document = new FileDocument("src/test/resources/validation/dss1792.asice");
	
	@Test
	public void validationTest() {
		
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(document);
		validator.setCertificateVerifier(getOfflineCertificateVerifier());
		
		Reports reports = validator.validateDocument();
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		
		assertEquals(2, diagnosticData.getTimestampList().size());
		boolean archiveTimestampFound = false;
		for (TimestampWrapper timestamp : diagnosticData.getTimestampList()) {
			if (timestamp.getType().isArchivalTimestamp()) {
				archiveTimestampFound = true;
			}
		}
		assertTrue(archiveTimestampFound);
		
		List<SignatureWrapper> signatureWrappers = diagnosticData.getSignatures();
		assertEquals(2, signatureWrappers.size());
		
		for (SignatureWrapper signature : signatureWrappers) {
			List<XmlDigestMatcher> digestMatchers = signature.getDigestMatchers();
			assertNotNull(digestMatchers);
			for (XmlDigestMatcher digestMatcher : digestMatchers) {
				assertTrue(digestMatcher.isDataFound());
				assertTrue(digestMatcher.isDataIntact());
			}
			if ("META-INF/signature001.p7s".equals(signature.getSignatureFilename())) {
				assertEquals(3, digestMatchers.size());
			} else if ("META-INF/signature002.p7s".equals(signature.getSignatureFilename())) {
				assertEquals(7, digestMatchers.size());
			} else {
    			fail("Unexpected signature found with name : " + signature.getSignatureFilename());
			}
		}
		
	}
	
	@Test
	public void manifestExtractorTest() {
		
        AbstractASiCContainerExtractor extractor = new ASiCWithCAdESContainerExtractor(document);
        ASiCExtractResult result = extractor.extract();
        
        List<DSSDocument> manifestFiles = result.getManifestDocuments();
        assertEquals(3, manifestFiles.size());
        
        List<DSSDocument> archiveManifestFiles = result.getArchiveManifestDocuments();
        assertEquals(0, archiveManifestFiles.size());
        
        List<DSSDocument> allManifestFiles = result.getAllManifestDocuments();
        assertEquals(3, allManifestFiles.size());
        
        for (DSSDocument manifest : allManifestFiles) {
        	ManifestFile manifestFile = ASiCEWithCAdESManifestParser.getManifestFile(manifest);
        	switch (manifestFile.getFilename()) {
        		case "META-INF/ASiCManifest.xml":
        			assertEquals("META-INF/signature001.p7s", manifestFile.getSignatureFilename());
        			assertFalse(manifestFile.isTimestampManifest());
        			assertFalse(manifestFile.isArchiveManifest());
        			break;
        		case "META-INF/ASiCManifest1.xml":
        			assertEquals("META-INF/timestamp001.tst", manifestFile.getSignatureFilename());
        			assertTrue(manifestFile.isTimestampManifest());
        			assertFalse(manifestFile.isArchiveManifest());
        			break;
        		case "META-INF/ASiCManifest2.xml":
        			assertEquals("META-INF/signature002.p7s", manifestFile.getSignatureFilename());
        			assertFalse(manifestFile.isTimestampManifest());
        			assertFalse(manifestFile.isArchiveManifest());
        			break;
        		default:
        			fail("Unexpected manifest found with name : " + manifestFile.getFilename());
        	}
        }
        
        assertEquals(2, result.getSignedDocuments().size());
		
	}

	@Override
	protected String getSigningAlias() {
		return null;
	}

}
