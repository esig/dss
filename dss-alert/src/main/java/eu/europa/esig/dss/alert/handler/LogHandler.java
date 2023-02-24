/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * 
 * This file is part of the "DSS - Digital Signature Services" project.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.alert.handler;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.event.Level;

import java.util.Objects;

/**
 * Implementation of {@code AlertHandler} which logs the object with the
 * specified {@code Level}
 *
 * @param <T> the object to execute logging based on
 */
public class LogHandler<T> implements AlertHandler<T> {

	private static final Logger LOG = LoggerFactory.getLogger(LogHandler.class);

	/** The level of a log */
	private final Level level;

	/**
	 * The constructor used to log with a {@code Level.WARN}
	 */
	public LogHandler() {
		this(Level.WARN);
	}

	/**
	 * The default constructor
	 *
	 * @param level {@link Level} of the log
	 */
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
