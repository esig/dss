package eu.europa.esig.dss.alert.handler;

import eu.europa.esig.dss.alert.exception.AlertException;

/**
 * Handler which throws an {@code AlertException}
 * 
 * @param <T>
 */
public class ThrowAlertExceptionHandler<T> implements AlertHandler<T> {

	@Override
	public void process(T object) {
		throw new AlertException(object.toString());
	}

}
