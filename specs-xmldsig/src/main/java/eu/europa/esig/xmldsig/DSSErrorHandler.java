package eu.europa.esig.xmldsig;

import java.util.ArrayList;
import java.util.List;

import org.xml.sax.ErrorHandler;
import org.xml.sax.SAXException;
import org.xml.sax.SAXParseException;

public class DSSErrorHandler implements ErrorHandler {

	private final List<SAXException> errors = new ArrayList<>();

	@Override
	public void error(SAXParseException arg0) throws SAXException {
		addExceptionMessage(arg0);
	}

	@Override
	public void fatalError(SAXParseException arg0) throws SAXException {
		addExceptionMessage(arg0);
	}

	@Override
	public void warning(SAXParseException arg0) throws SAXException {
		addExceptionMessage(arg0);
	}

	private void addExceptionMessage(SAXParseException e) {
		errors.add(e);
	}

	/**
	 * Returns a list of exceptions occurred during the validation process. 
	 * An empty list of the validation succeeded.
	 * 
	 * @return a list of {@link SAXParseException} exceptions
	 */
	public List<SAXException> getExceptions() {
		return errors;
	}

}
