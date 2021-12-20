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
package eu.europa.esig.dss.asic.cades.signature;

import eu.europa.esig.dss.asic.common.signature.GetDataToSignHelper;
import eu.europa.esig.dss.model.DSSDocument;

import java.util.List;

/**
 * The interface defining a helper to create a {@code ToBeSigned} data for an ASiC with CAdES
 */
public interface GetDataToSignASiCWithCAdESHelper extends GetDataToSignHelper {

	/**
	 * Returns a signed file document
	 *
	 * NOTE: In CMS/CAdES, only one file can be signed
	 *
	 * @return {@link DSSDocument} to sign
	 */
	DSSDocument getToBeSigned();

	/**
	 * Returns a list of detached documents
	 *
	 * NOTE: In case of ASiC-S signature, we need the detached content
	 *
	 * @return a list of detached {@link DSSDocument}s
	 */
	List<DSSDocument> getDetachedContents();

}
