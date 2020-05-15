package eu.europa.esig.dss.pades.validation;

import java.io.IOException;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.pades.exception.InvalidPasswordException;
import eu.europa.esig.dss.pdf.PdfDocumentReader;
import eu.europa.esig.dss.pdf.openpdf.ITextDocumentReader;

public class DSS1823Test extends DSS1823 {

	@Override
	protected PdfDocumentReader loadPDFDocument(DSSDocument dssDocument) {
		try {
			return new ITextDocumentReader(dssDocument);
		} catch (InvalidPasswordException | IOException e) {
			throw new DSSException("Unable to load document");
		}
	}

}
