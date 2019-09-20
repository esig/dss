package eu.europa.esig.dss.tsl.cache.state;

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

}
