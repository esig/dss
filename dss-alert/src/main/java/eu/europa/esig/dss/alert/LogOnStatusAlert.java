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
package eu.europa.esig.dss.alert;

import org.slf4j.event.Level;

import eu.europa.esig.dss.alert.handler.LogHandler;
import eu.europa.esig.dss.alert.status.Status;

/**
 * The class logs a message on {@code Status} alert
 */
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
