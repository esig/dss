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
package eu.europa.esig.dss.spi.validation;

import java.io.Serializable;
import java.util.List;

/**
 * Defined a "signed-signature-element" or "unsigned-signature-element" of a signature
 *
 * @param <SA> implementation of a signature attribute (signed or unsigned) corresponding to the current signature format
 */
public interface SignatureProperties<SA extends SignatureAttribute> extends Serializable {
	
	/**
	 * Checks if "unsigned-signature-properties" exists and can be processed
	 * @return TRUE if the element exists, FALSE otherwise
	 */
	boolean isExist();
	
	/**
	 * Returns a list of children contained in the element
	 * @return list of {@link SignatureAttribute}s
	 */
	List<SA> getAttributes();

}
