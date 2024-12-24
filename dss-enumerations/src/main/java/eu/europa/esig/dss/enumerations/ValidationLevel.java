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
package eu.europa.esig.dss.enumerations;

/**
 * The target validation level as per EN 319 102-1
 *
 * NOTE: the validation process "stops" processing on the chosen level
 *
 */
public enum ValidationLevel {

	/**
	 * Validation as per "5.3 Validation process for Basic Signatures"
	 */
	BASIC_SIGNATURES,

	/**
	 * Validation as per "5.4 Time-stamp validation building block"
	 */
	TIMESTAMPS,

	/**
	 * Validation as per "5.5 Validation process for Signatures with Time and
	 * Signatures with Long-Term Validation Material"
	 */
	LONG_TERM_DATA,

	/**
	 * Validation as per "5.6 Validation process for Signatures providing Long Term Availability
	 * and Integrity of Validation Material"
	 */
	ARCHIVAL_DATA;

}
