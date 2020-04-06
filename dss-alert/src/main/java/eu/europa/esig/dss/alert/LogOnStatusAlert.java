package eu.europa.esig.dss.alert;

import org.slf4j.event.Level;

import eu.europa.esig.dss.alert.handler.LogHandler;
import eu.europa.esig.dss.alert.status.Status;

public class LogOnStatusAlert extends AbstractStatusAlert {

	/**
	 * Default constructor which LOG with WARN
	 */
	public LogOnStatusAlert() {
		super(new LogHandler<Status>());
	}

	/**
	 * Additional constructor which uses the specified level to LOG
	 * 
	 * @param level the log level to be used
	 */
	public LogOnStatusAlert(Level level) {
		super(new LogHandler<Status>(level));
	}

}
