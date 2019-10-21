package eu.europa.esig.dss.tsl.cache.state;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.Date;
import java.util.Objects;

public class CachedException {

	private final Date date = new Date();
	private final Exception exception;

	public CachedException(Exception exception) {
		Objects.requireNonNull(exception);
		this.exception = exception;
	}

	public Date getDate() {
		return date;
	}

	public Exception getException() {
		return exception;
	}
	
	public String getExceptionMessage() {
		return exception.getLocalizedMessage();
	}
	
	public String getStackTrace() {
		StringWriter sw = new StringWriter();
		PrintWriter pw = new PrintWriter(sw);
		exception.printStackTrace(pw);
		return sw.toString();
	}

}
