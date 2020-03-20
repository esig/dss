package eu.europa.esig.dss.alert.handler;

import eu.europa.esig.dss.alert.exception.AlertException;

/**
 * The default DSSExceptionAlert handler allowing to re-throw the raised exception
 * Keeps RuntimeException unchanged, re-throws AlertException for others
 *
 */
public class ExceptionAlertHandler implements AlertHandler<Exception> {

	@Override
	public void process(Exception e) {
		if (e instanceof RuntimeException) {
			throw (RuntimeException) e;
		} else {
			throw new AlertException(e);
		}
	}

}
