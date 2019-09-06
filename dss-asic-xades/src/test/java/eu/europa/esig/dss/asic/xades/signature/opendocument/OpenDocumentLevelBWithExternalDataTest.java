package eu.europa.esig.dss.asic.xades.signature.opendocument;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

import eu.europa.esig.dss.asic.common.ASiCUtils;
import eu.europa.esig.dss.asic.xades.ASiCWithXAdESSignatureParameters;
import eu.europa.esig.dss.asic.xades.signature.ASiCWithXAdESService;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;

@RunWith(Parameterized.class)
public class OpenDocumentLevelBWithExternalDataTest extends AbstractOpenDocumentTestSignature {

	public OpenDocumentLevelBWithExternalDataTest(File fileToTest) {
		super(fileToTest);
	}

	private DSSDocument fileToTest;
	private DocumentSignatureService<ASiCWithXAdESSignatureParameters> service;
	private ASiCWithXAdESSignatureParameters signatureParameters;
	
	@Parameters(name = "Validation {index} : {0}")
	public static Collection<Object[]> data() {
		File file = new File("src/test/resources/signable/open-document-external-data.odt");
		Collection<Object[]> dataToRun = new ArrayList<Object[]>();
		dataToRun.add(new Object[] { file });
		return dataToRun;
	}

	@Before
	public void init() {
		fileToTest = new FileDocument(new File("src/test/resources/signable/open-document-external-data.odt"));

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
	@Override
	public void signAndVerify() throws IOException {
		super.signAndVerify();
	}

	@Override
	protected void onDocumentSigned(byte[] byteArray) {
		super.onDocumentSigned(byteArray);

		// Both validations must be valid, even after deleting files from external-data
		// OpenDocument Part 1 CH 3.16
		DSSDocument signedDocument = new InMemoryDocument(byteArray);
		signedDocument = removeExternalDataFilesFromContainer(signedDocument);

		SignedDocumentValidator validator = getValidator(signedDocument);
		validator.setCertificateVerifier(getCompleteCertificateVerifier());
		Reports reports = validator.validateDocument();
		verifyDiagnosticData(reports.getDiagnosticData());
	}

	protected DSSDocument removeExternalDataFilesFromContainer(DSSDocument archiveDocument) {
		try (ByteArrayOutputStream baos = new ByteArrayOutputStream();
				ZipOutputStream zos = new ZipOutputStream(baos)) {
			copyArchiveContentWithoutExternalData(archiveDocument, zos);

			zos.finish();

			return new InMemoryDocument(baos.toByteArray(), null, archiveDocument.getMimeType());
		} catch (IOException e) {
			throw new DSSException("Unable to extend the ASiC container", e);
		}
	}

	private void copyArchiveContentWithoutExternalData(DSSDocument archiveDocument, ZipOutputStream zos)
			throws IOException {
		long containerSize = DSSUtils.getFileByteSize(archiveDocument);
		try (InputStream is = archiveDocument.openStream(); ZipInputStream zis = new ZipInputStream(is)) {
			ZipEntry entry;
			while ((entry = ASiCUtils.getNextValidEntry(zis)) != null) {
				final String name = entry.getName();
				final ZipEntry newEntry = new ZipEntry(name);
				if (!name.equals("external-data/test.txt")) {
					zos.putNextEntry(newEntry);
					ASiCUtils.secureCopy(zis, zos, containerSize);
				}
			}
		}
	}

	@Override
	protected DSSDocument getDocumentToSign() {
		return fileToTest;
	}

	@Override
	protected DocumentSignatureService<ASiCWithXAdESSignatureParameters> getService() {
		return service;
	}

	@Override
	protected ASiCWithXAdESSignatureParameters getSignatureParameters() {
		return signatureParameters;
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}
