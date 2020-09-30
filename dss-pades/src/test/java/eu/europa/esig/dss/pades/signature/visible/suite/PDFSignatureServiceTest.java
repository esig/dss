package eu.europa.esig.dss.pades.signature.visible.suite;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.alert.LogOnStatusAlert;
import eu.europa.esig.dss.alert.exception.AlertException;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.pades.SignatureFieldParameters;
import eu.europa.esig.dss.pdf.AbstractPDFSignatureService;
import eu.europa.esig.dss.pdf.IPdfObjFactory;
import eu.europa.esig.dss.pdf.ServiceLoaderPdfObjFactory;

public class PDFSignatureServiceTest {
	
	private AbstractPDFSignatureService service;
	
	@BeforeEach
	public void init() {
		IPdfObjFactory pdfObjFactory = new ServiceLoaderPdfObjFactory();
		service = (AbstractPDFSignatureService) pdfObjFactory.newPAdESSignatureService();
	}
	
	@Test
	public void alertOnSignatureFieldOverlapTest() throws IOException {
		DSSDocument documentToSign = new InMemoryDocument(getClass().getResourceAsStream("/EmptyPage.pdf"));
		
		SignatureFieldParameters parametersOne = new SignatureFieldParameters();
		parametersOne.setFieldId("signature1");
		parametersOne.setOriginX(0);
		parametersOne.setOriginY(0);
		parametersOne.setHeight(100);
		parametersOne.setWidth(100);
		DSSDocument withFirstField = service.addNewSignatureField(documentToSign, parametersOne);
		assertNotNull(withFirstField);
		
		SignatureFieldParameters parametersTwo = new SignatureFieldParameters();
		parametersTwo.setOriginX(25);
		parametersTwo.setOriginY(25);
		parametersTwo.setHeight(100);
		parametersTwo.setWidth(100);
		parametersTwo.setFieldId("signature2");
		Exception exception = assertThrows(AlertException.class, () -> service.addNewSignatureField(withFirstField, parametersTwo));
		assertEquals("The new signature field position overlaps with an existing annotation!", exception.getMessage());
	
		service.setAlertOnSignatureFieldOverlap(new LogOnStatusAlert());
		DSSDocument withSecondField = service.addNewSignatureField(withFirstField, parametersTwo);
		assertNotNull(withSecondField);
		
		assertEquals(2, service.getAvailableSignatureFields(withSecondField).size());
	}

}
