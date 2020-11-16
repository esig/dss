package eu.europa.esig.xmldsig.exception;

import java.util.ArrayList;
import java.util.List;

import org.xml.sax.SAXException;

public class XSDValidationException extends Exception {

	private static final long serialVersionUID = 4928003472348809475L;

	private final List<SAXException> exceptions;

	public XSDValidationException(List<SAXException> exceptions) {
		super();
		this.exceptions = exceptions;
	}

	public List<String> getAllMessages() {
		List<String> messages = new ArrayList<>();
		if (exceptions != null && exceptions.size() > 0) {
			for (SAXException e : exceptions) {
				messages.add(e.getMessage());
			}
		}
		return messages;
	}

	@Override
	public String getMessage() {
		List<String> allMessages = getAllMessages();
		if (allMessages != null && allMessages.size() > 0) {
			return allMessages.toString();
		}
		return null;
	}

}
