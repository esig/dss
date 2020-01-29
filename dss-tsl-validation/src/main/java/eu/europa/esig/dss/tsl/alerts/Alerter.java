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
package eu.europa.esig.dss.tsl.alerts;

import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.spi.tsl.TLValidationJobSummary;

public class Alerter {

	private static final Logger LOG = LoggerFactory.getLogger(Alerter.class);

	private List<Alert<?>> alerts;
	private TLValidationJobSummary jobSummary;

	public Alerter(TLValidationJobSummary jobSummary, List<Alert<?>> alerts) {
		this.alerts = alerts;
		this.jobSummary = jobSummary;
	}

	public void detectChanges() {
		for (Alert<?> alert : alerts) {
			try {
				alert.detectAndAlert(jobSummary);
			} catch (Exception e) {
				LOG.warn("An error occurred while trying to detect changes inside a TL or LOTL.", e);
			}
		}
	}
}
