package eu.europa.esig.dss.jaxb.exception;

import java.util.Collections;
import java.util.List;

public class XSDValidationException extends RuntimeException {

	private static final long serialVersionUID = 4928003472348809475L;

	private final List<String> exceptionMessages;

	public XSDValidationException(List<String> exceptionMessages) {
		super();
		this.exceptionMessages = exceptionMessages;
	}

	public List<String> getAllMessages() {
		if (exceptionMessages == null) {
			return Collections.emptyList();
		}
		return exceptionMessages;
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
