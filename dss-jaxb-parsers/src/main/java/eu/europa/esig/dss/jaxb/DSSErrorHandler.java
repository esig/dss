package eu.europa.esig.dss.jaxb;

import org.xml.sax.ErrorHandler;
import org.xml.sax.SAXException;
import org.xml.sax.SAXParseException;

import java.util.ArrayList;
import java.util.List;

/**
 * The default {@code ErrorHandler} used to collect the occurred during 
 * the validation errors
 *
 */
public class DSSErrorHandler implements ErrorHandler {

	/** List of error exceptions */
	private final List<SAXException> errors = new ArrayList<>();

	/** List of fatal error exceptions */
	private final List<SAXException> fatalErrors = new ArrayList<>();

	/** List of warning exceptions */
	private final List<SAXException> warnings = new ArrayList<>();

	@Override
	public void error(SAXParseException arg0) throws SAXException {
		errors.add(arg0);
	}

	@Override
	public void fatalError(SAXParseException arg0) throws SAXException {
		fatalErrors.add(arg0);
	}

	@Override
	public void warning(SAXParseException arg0) throws SAXException {
		warnings.add(arg0);
	}

	/**
	 * Returns a list of errors occurred during the validation process. An empty
	 * list of the validation succeeded.
	 * 
	 * @return a list of {@link SAXParseException} exceptions
	 */
	public List<SAXException> getErrors() {
		return errors;
	}

	/**
	 * Returns a list of fatal errors occurred during the validation process. An
	 * empty list of the validation succeeded.
	 * 
	 * @return a list of {@link SAXParseException} exceptions
	 */
	public List<SAXException> getFatalErrors() {
		return fatalErrors;
	}

	/**
	 * Returns a list of warnings occurred during the validation process. An empty
	 * list of the validation succeeded.
	 * 
	 * @return a list of {@link SAXParseException} exceptions
	 */
	public List<SAXException> getWarnings() {
		return warnings;
	}

	/**
	 * Checks if the validation succeeded (no errors or warning received)
	 * 
	 * @return TRUE if validation succeed, FALSE otherwise
	 */
	public boolean isValid() {
		return errors.isEmpty() && fatalErrors.isEmpty() && warnings.isEmpty();
	}

}
