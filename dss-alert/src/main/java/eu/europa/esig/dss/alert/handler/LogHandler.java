package eu.europa.esig.dss.alert.handler;

import java.util.Objects;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.event.Level;

/**
 * Implementation of {@code AlertHandler} which logs the object with the
 * specified {@code Level}
 */
public class LogHandler<T> implements AlertHandler<T> {

	private static final Logger LOG = LoggerFactory.getLogger(LogHandler.class);

	private final Level level;

	public LogHandler() {
		this(Level.WARN);
	}

	public LogHandler(Level level) {
		Objects.requireNonNull(level);
		this.level = level;
	}

	@Override
	public void process(T object) {
		switch (level) {
		case TRACE:
			LOG.trace(object.toString());
			break;
		case DEBUG:
			LOG.debug(object.toString());
			break;
		case INFO:
			LOG.info(object.toString());
			break;
		case WARN:
			LOG.warn(object.toString());
			break;
		case ERROR:
			LOG.error(object.toString());
			break;
		default:
			throw new IllegalArgumentException(String.format("The LogLevel [%s] is not allowed configuration!", level));
		}
	}

}
