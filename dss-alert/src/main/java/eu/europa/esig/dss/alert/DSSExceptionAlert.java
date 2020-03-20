package eu.europa.esig.dss.alert;

import eu.europa.esig.dss.alert.handler.ExceptionAlertHandler;

/**
 * The default alert to re-throw a caused exception
 *
 */
public class DSSExceptionAlert extends ExceptionAlert {

	public DSSExceptionAlert() {
		super(new ExceptionAlertHandler());
	}

}
