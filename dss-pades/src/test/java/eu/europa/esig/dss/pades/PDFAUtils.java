package eu.europa.esig.dss.pades;

import java.io.IOException;
import java.io.InputStream;
import java.util.List;

import org.apache.pdfbox.preflight.PreflightDocument;
import org.apache.pdfbox.preflight.ValidationResult;
import org.apache.pdfbox.preflight.ValidationResult.ValidationError;
import org.apache.pdfbox.preflight.parser.PreflightParser;
import org.apache.pdfbox.preflight.utils.ByteArrayDataSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSException;

public final class PDFAUtils {

	private static final Logger LOG = LoggerFactory.getLogger(PDFAUtils.class);

	private PDFAUtils() {
	}

	public static boolean validatePDFAStructure(DSSDocument signedDocument) {
		try (InputStream is = signedDocument.openStream()) {
			PreflightParser parser = new PreflightParser(new ByteArrayDataSource(is));
			parser.parse();
			PreflightDocument preflightDocument = parser.getPreflightDocument();
			preflightDocument.validate();
			ValidationResult result = preflightDocument.getResult();
			List<ValidationError> errorsList = result.getErrorsList();
			for (ValidationError validationError : errorsList) {
				LOG.info(validationError.getDetails());
			}
			return result.isValid();
		} catch (IOException e) {
			throw new DSSException("Unable to validate PDFA structure", e);
		}
	}
}
