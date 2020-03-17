package eu.europa.esig.dss.alert;

import eu.europa.esig.dss.alert.detector.AlertDetector;
import eu.europa.esig.dss.alert.handler.AlertHandler;

/**
 * The class allowing to handle Exceptions in a custom way
 *
 */
public class ExceptionAlert extends AbstractAlert<Exception> {

	/**
	 * The default constructor
	 * 
	 * @param handler 
	 */
	public ExceptionAlert(AlertHandler<Exception> handler) {
		super(new ExceptionDetector(), handler);
	}
	
	/**
	 * The default Detector for ExceptionAlert
	 */
	static class ExceptionDetector implements AlertDetector<Exception> {

		@Override
		public boolean detect(Exception e) {
			return e != null;
		}
		
	}

}
