/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.validation.process.vpfswatsp;

import eu.europa.esig.dss.diagnostic.jaxb.XmlTimestampedObject;

import java.util.Collections;
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
	 * Returns an Id of a token providing the POE (e.g. a time-stamp Id)
	 * NOTE: if the POE is not provided by a token (e.g. validation time POE), returns NULL value
	 *
	 * @return {@link String}
	 */
	public String getPOEProviderId() {
		return null;
	}
	
	/**
	 * Returns a list of objects covered by the POE if applicable
	 * NOTE: returns NULL if the POE is defined by a control time
	 *
	 * @return a list of {@link XmlTimestampedObject}s
	 */
	public List<XmlTimestampedObject> getPOEObjects() {
		return Collections.emptyList();
	}
	
	/**
	 * Returns whether the POE is provided by a token (i.e. a time-stamp or an evidence record)
	 *
	 * @return TRUE if the POE is provided by a token, FALSE otherwise
	 */
	public boolean isTokenProvided() {
		return false;
	}

}
