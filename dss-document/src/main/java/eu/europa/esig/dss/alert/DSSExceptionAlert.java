package eu.europa.esig.dss.alert;

import eu.europa.esig.dss.alert.handler.AlertHandler;
import eu.europa.esig.dss.model.DSSException;

/**
 * The default alert to re-throw a caused exception
 *
 */
public class DSSExceptionAlert extends ExceptionAlert {

	public DSSExceptionAlert() {
		super(new DSSExceptionAlertHandler());
	}
	
	static class DSSExceptionAlertHandler implements AlertHandler<Exception> {

		@Override
		public void process(Exception e) {
			if (e instanceof DSSException) {
				throw (DSSException) e;
			} else {
				throw new DSSException(e);
			}
		}
		
	}

}
