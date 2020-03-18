package eu.europa.esig.dss.alert.handler.log;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.event.Level;

import eu.europa.esig.dss.alert.handler.AlertHandler;

/**
 * Allows to configure a logger on a raised exception
 * @author aleksandr.beliakov
 *
 */
public class LogExceptionAlertHandler implements AlertHandler<Exception> {

	private static final Logger LOG = LoggerFactory.getLogger(LogExceptionAlertHandler.class);
	
	private final Level level;
	private final boolean stackTraceEnabled;
	
	/**
	 * The default constructor to instantiate a LogExceptionAlertHandler
	 * 
	 * @param level {@code Level} defines an expected log level
	 * @param enableStackTrace defines if the stackTrace must be added to the log message
	 */
	public LogExceptionAlertHandler(Level level, boolean enableStackTrace) {
		this.level = level;
		this.stackTraceEnabled = enableStackTrace;
	}

	@Override
	public void process(Exception e) {
		Object[] args = {};
		if (stackTraceEnabled) {
			args = new Object[] { e };
		}
		switch (level) {
			case TRACE:
				LOG.trace(e.getMessage(), args);
				break;
			case DEBUG:
				LOG.debug(e.getMessage(), args);
				break;
			case INFO:
				LOG.info(e.getMessage(), args);
				break;
			case WARN:
				LOG.warn(e.getMessage(), args);
				break;
			case ERROR:
				LOG.error(e.getMessage(), args);
				break;
			default:
				throw new IllegalArgumentException(String.format("The LogLevel [%s] is not allowed configuration!", level));
		}
	}

}
