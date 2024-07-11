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
package eu.europa.esig.dss.enumerations;

/**
 * Mask generation function.
 *
 * @deprecated since DSS 6.1. To be removed later. For MGF1 use EncryptionAlgorithm.RSASSA_PSS option instead
 */
@Deprecated
public enum MaskGenerationFunction {

	/** Mask Generation Function 1 */
	MGF1("MGF1");

	/** Name of the Mask Generation Function */
	private final String name;

	/**
	 * Default constructor
	 *
	 * @param name {@link String}
	 */
	MaskGenerationFunction(String name) {
		this.name = name;
	}

	/**
	 * Returns name of the MaskGenerationFunction
	 *
	 * @return {@link String} name
	 */
	public String getName() {
		return name;
	}

}
