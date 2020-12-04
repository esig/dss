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
package eu.europa.esig.dss.signature;

/**
 * Defines the performing signature operation
 */
public enum SigningOperation {

	/**
	 * Signature creation
	 */
	SIGN,
	
	/**
	 * Counter signature creation
	 */
	COUNTER_SIGN,

	/**
	 * Timestamp creation
	 */
	TIMESTAMP,

	/**
	 * Extension process (eg : signature basic (B-P-B) to signature with timestamp
	 * (B-P-T))
	 */
	EXTEND,
	
	/**
	 * The signature policy store addition
	 */
	ADD_SIG_POLICY_STORE;

}
