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
package eu.europa.esig.dss.spi.tsl;

import java.io.Serializable;
import java.util.Date;

/**
 * Describes a state of a record
 */
public interface InfoRecord extends Serializable {

	/**
	 * Gets if the refresh is needed for an entry
	 *
	 * @return TRUE if the refresh is needed, FALSE otherwise
	 */
	boolean isRefreshNeeded();

	/**
	 * Gets if the record is desynchronized
	 *
	 * @return TRUE if the record is desynchronized, FALSE otherwise
	 */
	boolean isDesynchronized();

	/**
	 * Gets if the record is synchronized
	 *
	 * @return TRUE if the record is synchronized, FALSE otherwise
	 */
	boolean isSynchronized();

	/**
	 * Gets if the error is present for the record
	 *
	 * @return TRUE if the record defines an error, FALSE otherwise
	 */
	boolean isError();

	/**
	 * Gets if the record shall be deleted
	 *
	 * @return TRUE if the record shall be deleted, FALSE otherwise
	 */
	boolean isToBeDeleted();

	/**
	 * Gets the record's status name
	 *
	 * @return {@link String}
	 */
	String getStatusName();

	/**
	 * Gets the last time when the state of record has been changed
	 *
	 * @return {@link Date}
	 */
	Date getLastStateTransitionTime();

	/**
	 * Gets the last time when the record has been synchronized
	 *
	 * @return {@link Date}
	 */
	Date getLastSuccessSynchronizationTime();

	/**
	 * Gets the exception message for an error state
	 *
	 * @return {@link String}
	 */
	String getExceptionMessage();

	/**
	 * Gets the exception stack trace for an error state
	 *
	 * @return {@link String}
	 */
	String getExceptionStackTrace();

	/**
	 * Gets the first time when the error is occurred
	 *
	 * @return {@link Date}
	 */
	Date getExceptionFirstOccurrenceTime();

	/**
	 * Gets the last time when the error is occurred
	 *
	 * @return {@link Date}
	 */
	Date getExceptionLastOccurrenceTime();

	/**
	 * Gets if a result exist under the record
	 *
	 * @return TRUE if the result exists, FALSE otherwise
	 */
	boolean isResultExist();

}
