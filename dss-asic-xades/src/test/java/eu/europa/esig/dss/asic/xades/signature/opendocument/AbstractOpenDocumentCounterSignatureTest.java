package eu.europa.esig.dss.asic.xades.signature.opendocument;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.stream.Stream;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import eu.europa.esig.dss.asic.common.ASiCExtractResult;
import eu.europa.esig.dss.asic.common.validation.AbstractASiCContainerValidator;
import eu.europa.esig.dss.asic.xades.ASiCWithXAdESContainerExtractor;
import eu.europa.esig.dss.asic.xades.signature.AbstractASiCXAdESCounterSignatureTest;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.MimeType;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.SignedDocumentValidator;

public abstract class AbstractOpenDocumentCounterSignatureTest extends AbstractASiCXAdESCounterSignatureTest {
	
	private DSSDocument fileToTest;
	
	private static Stream<Arguments> data() {
		File folder = new File("src/test/resources/opendocument");
		Collection<File> listFiles = Utils.listFiles(folder,
				new String[] { "odt", "ods", "odp", "odg" }, true);
		

		List<Arguments> args = new ArrayList<>();
		for (File file : listFiles) {
			args.add(Arguments.of(new FileDocument(file)));
		}
		return args.stream();
	}
	
	@ParameterizedTest(name = "Validation {index} : {0}")
	@MethodSource("data")
	public void test(DSSDocument fileToTest) {
		this.fileToTest = fileToTest;

		super.signAndVerify();
	}

	@Override
	public void signAndVerify() {
	}

	@Override
	protected DSSDocument getDocumentToSign() {
		return fileToTest;
	}
	
	@Override
	protected MimeType getExpectedMime() {
		return getDocumentToSign().getMimeType();
	}

	@Override
	protected List<DSSDocument> getOriginalDocuments() {
		return Collections.singletonList(getDocumentToSign());
	}
	
	@Override
	protected void verifyOriginalDocuments(SignedDocumentValidator validator, DiagnosticData diagnosticData) {
		
		ASiCWithXAdESContainerExtractor extractor = new ASiCWithXAdESContainerExtractor(getOriginalDocuments().get(0));
		ASiCExtractResult extractOriginal = extractor.extract();
		
		AbstractASiCContainerValidator asicValidator = (AbstractASiCContainerValidator) validator;
		List<DSSDocument> signedDocuments = asicValidator.getSignedDocuments();
		
		List<String> fileNames = getSignedFilesNames(signedDocuments);		
		List<String> fileDigests = getSignedFilesDigests(signedDocuments);

		for (DSSDocument doc : extractOriginal.getSignedDocuments()) {
			assertTrue(fileNames.contains(doc.getName()));
			assertTrue(fileDigests.contains(doc.getDigest(DigestAlgorithm.SHA256)));
		}	
		
		verifySignatureFileName(asicValidator.getSignatureDocuments());
	}
	
	private List<String> getSignedFilesNames(List<DSSDocument> files) {
		List<String> fileNames = new ArrayList<>();
		for(DSSDocument doc: files) {
			fileNames.add(doc.getName());
		}
		return fileNames;
	}
	
	private List<String> getSignedFilesDigests(List<DSSDocument> files) {
		List<String> fileDigests = new ArrayList<>();
		for(DSSDocument doc: files) {
			fileDigests.add(doc.getDigest(DigestAlgorithm.SHA256));
		}
		return fileDigests;
	}
	
	public void verifySignatureFileName(List<DSSDocument> signatureFiles) {
		assertEquals(1, signatureFiles.size());
		DSSDocument signature = signatureFiles.get(0);
		assertEquals("META-INF/documentsignatures.xml", signature.getName());
	}

}
