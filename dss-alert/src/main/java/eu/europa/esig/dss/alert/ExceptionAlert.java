package eu.europa.esig.dss.alert;

import eu.europa.esig.dss.alert.detector.ExceptionDetector;
import eu.europa.esig.dss.alert.handler.AlertHandler;

/**
 * The class allowing to handle Exceptions in a custom way
 *
 */
public class ExceptionAlert extends AbstractAlert<Exception> {

	/**
	 * The default constructor
	 * 
	 * @param handler {@link AlertHandler}
	 */
	public ExceptionAlert(AlertHandler<Exception> handler) {
		super(new ExceptionDetector(), handler);
	}

}
