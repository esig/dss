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
package eu.europa.esig.dss.asic.common.definition;

import eu.europa.esig.dss.definition.AbstractPaths;

/**
 * Contains paths for an ASiC scheme
 */
public class ASiCPaths extends AbstractPaths {

	private static final long serialVersionUID = 2410165510311258998L;

	/**
	 * "./asic:ASiCManifest"
	 */
	public static final String ASIC_MANIFEST_PATH = fromCurrentPosition(ASiCElement.ASIC_MANIFEST);

	/**
	 * "./asic:DataObjectReference"
	 */
	public static final String DATA_OBJECT_REFERENCE_PATH = fromCurrentPosition(ASiCElement.DATA_OBJECT_REFERENCE);
	
	/**
	 * "./asic:SigReference"
	 */
	public static final String SIG_REFERENCE_PATH = fromCurrentPosition(ASiCElement.SIG_REFERENCE);

	/**
	 * "./asic:SigReference@URI"
	 */
	public static final String SIG_REFERENCE_URI_PATH = fromCurrentPosition(ASiCElement.SIG_REFERENCE, ASiCAttribute.URI);

	/**
	 * Default constructor
	 */
	public ASiCPaths() {
	}
	
}
