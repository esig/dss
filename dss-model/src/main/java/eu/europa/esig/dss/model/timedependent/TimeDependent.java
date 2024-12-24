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
package eu.europa.esig.dss.model.timedependent;

import java.io.Serializable;
import java.util.Date;

/**
 * Valid in a specific time interval.
 * 
 * @author jdvorak
 */
public interface TimeDependent extends Serializable {

	/**
	 * The start of the validity period.
	 * It shall never be null.
	 * 
	 * @return the start date of the validity period
	 */
	Date getStartDate();

	/**
	 * The end of the validity period.
	 * Null indicates that this is the last known case.
	 * If not null, it is assumed that the end date is not older than the start date.
	 * 
	 * @return the end date of the validity period or null if the object is still valid
	 */
	Date getEndDate();

}
