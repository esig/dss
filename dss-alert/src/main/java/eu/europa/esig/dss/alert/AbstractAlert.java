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

import eu.europa.esig.dss.alert.detector.AlertDetector;
import eu.europa.esig.dss.alert.handler.AlertHandler;

import java.util.Objects;

/**
 * The class contains a general logic for alert handling
 *
 * @param <T> the object to execute alert detection and handling on
 */
public abstract class AbstractAlert<T> implements Alert<T> {

	/** Serves as an event detector, in order to trigger the handler */
	private final AlertDetector<T> detector;

	/** Runs a custom code for the event */
	private final AlertHandler<T> handler;

	/**
	 * Empty constructor requiring implementation of {@code #getAlertDetector} and {@code #getAlertHandler} methods
	 */
	protected AbstractAlert() {
		this(null, null);
	}

	/**
	 * The default constructor setting the {@code detector} and {@code handler} explicitly
	 *
	 * @param detector {@link AlertDetector} to detect an event
	 * @param handler {@link AlertHandler} to execute the corresponding code
	 */
	protected AbstractAlert(AlertDetector<T> detector, AlertHandler<T> handler) {
		this.detector = detector;
		this.handler = handler;
	}

	@Override
	public void alert(T object) {
		if (getAlertDetector().detect(object)) {
			getAlertHandler().process(object);
		}
	}

	/**
	 * Gets the alert detector
	 *
	 * @return {@link AlertDetector}
	 */
	protected AlertDetector<T> getAlertDetector() {
		Objects.requireNonNull(detector, "AlertDetector shall be defined!");
		return detector;
	}

	/**
	 * Gets the alert handler
	 *
	 * @return {@link AlertHandler}
	 */
	protected AlertHandler<T> getAlertHandler() {
		Objects.requireNonNull(handler, "AlertHandler shall be defined!");
		return handler;

	}

}
