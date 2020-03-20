package eu.europa.esig.dss.alert.handler;

import eu.europa.esig.dss.alert.exception.AlertException;

/**
 * the default DSSExceptionAlert handler allowing to re-throw the raised exception
 *
 */
public class ExceptionAlertHandler implements AlertHandler<Exception> {

	@Override
	public void process(Exception e) {
		if (e instanceof AlertException) {
			throw (AlertException) e;
		} else {
			throw new AlertException(e);
		}
	}

}
