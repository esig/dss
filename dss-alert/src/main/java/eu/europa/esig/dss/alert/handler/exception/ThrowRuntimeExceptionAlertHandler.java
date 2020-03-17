package eu.europa.esig.dss.alert.handler.exception;

import eu.europa.esig.dss.alert.handler.AlertHandler;

/**
 * The alert handler throwing the original exception
 *
 */
public class ThrowRuntimeExceptionAlertHandler implements AlertHandler<Exception> {

	@Override
	public void process(Exception e) {
		if (e instanceof RuntimeException) {
			throw (RuntimeException) e;
		} else {
			throw new RuntimeException(e);
		}
	}

}
