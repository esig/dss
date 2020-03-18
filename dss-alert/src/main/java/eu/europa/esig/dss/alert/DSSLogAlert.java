package eu.europa.esig.dss.alert;

import org.slf4j.event.Level;

import eu.europa.esig.dss.alert.handler.log.LogExceptionAlertHandler;

/**
 * The default alert to log a caused exception
 *
 */
public class DSSLogAlert extends ExceptionAlert {

	/**
	 * The default constructor to create a DSSLogAlert
	 * 
	 * @param level {@link Level} to use
	 * @param enableStackTrace defines if a stackTrace has to be printed
	 */
	public DSSLogAlert(Level level, boolean enableStackTrace) {
		super(new LogExceptionAlertHandler(level, enableStackTrace));
	}

}
