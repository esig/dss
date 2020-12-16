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
package eu.europa.esig.dss.validation.process.vpfswatsp;

import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTimestampedObject;
import eu.europa.esig.dss.enumerations.TimestampType;

import java.util.Date;
import java.util.List;
import java.util.Objects;

/**
 * Contains Proof Of Existence for validation objects
 *
 */
public class POE {

	/** The POE time */
	private final Date poeTime;

	/** The POE provider */
	private TimestampWrapper timestampWrapper;
	
	/**
	 * The constructor to instantiate POE by a timestamp
	 * 
	 * @param timestampWrapper {@link TimestampWrapper}
	 */
	public POE(TimestampWrapper timestampWrapper) {
		Objects.requireNonNull(timestampWrapper, "The timestampWrapper must be defined!");
		this.timestampWrapper = timestampWrapper;
		this.poeTime = timestampWrapper.getProductionTime();
	}
	
	/**
	 * The constructor to instantiate a global POE by a control/validation time
	 * NOTE: the POE will be applied for all tokens
	 * 
	 * @param controlTime {@link Date}
	 */
	public POE(Date controlTime) {
		Objects.requireNonNull(controlTime, "The controlTime must be defined!");
		this.poeTime = controlTime;
	}
	
	/**
	 * Returns time of the POE
	 * 
	 * @return {@link Date}
	 */
	public Date getTime() {
		return poeTime;
	}
	
	/**
	 * Checks if the POE if a POE defined by a timestamp
	 * 
	 * @return true of the POE defined by a timesatmp, false otherwise
	 */
	public boolean isTimestampPoe() {
		return timestampWrapper != null;
	}
	
	/**
	 * Returns id of the timestamp if defined
	 * NOTE: returns NULL if the POE is defined by a control time
	 * 
	 * @return {@link String} timestamp id
	 */
	public String getTimestampId() {
		if (timestampWrapper != null) {
			return timestampWrapper.getId();
		}
		return null;
	}
	
	/**
	 * Returns timestamp type if the POE defined by a timestamp
	 * NOTE: returns NULL if the POE is defined by a control time
	 * 
	 * @return {@link TimestampType}
	 */
	public TimestampType getTimestampType() {
		if (timestampWrapper != null) {
			return timestampWrapper.getType();
		}
		return null;
	}
	
	/**
	 * Returns a list of timestamped objects if the POE defined by a timestamp
	 * NOTE: returns NULL if the POE is defined by a control time
	 * 
	 * @return a list of {@link XmlTimestampedObject}s
	 */
	public List<XmlTimestampedObject> getTimestampedObjects() {
		if (timestampWrapper != null) {
			return timestampWrapper.getTimestampedObjects();
		}
		return null;
		
	}

}
