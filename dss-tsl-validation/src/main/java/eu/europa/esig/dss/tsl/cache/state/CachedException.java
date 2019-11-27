package eu.europa.esig.dss.tsl.cache.state;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.Date;
import java.util.Objects;

public class CachedException {

	private final Date date = new Date();
	private Date lastOccurrenceDate = new Date();
	private final Exception exception;

	public CachedException(Exception exception) {
		Objects.requireNonNull(exception);
		this.exception = exception;
	}

	public Date getDate() {
		return date;
	}
	
	public Date getLastOccurrenceDate()  {
		return lastOccurrenceDate;
	}
	
	public void setLastOccurrenceDate(Date lastOccurrenceDate) {
		this.lastOccurrenceDate = lastOccurrenceDate;
	}

	public Exception getException() {
		return exception;
	}
	
	public String getExceptionMessage() {
		return exception.getMessage();
	}
	
	public String getStackTrace() {
		StringWriter sw = new StringWriter();
		PrintWriter pw = new PrintWriter(sw);
		exception.printStackTrace(pw);
		return sw.toString();
	}

}
