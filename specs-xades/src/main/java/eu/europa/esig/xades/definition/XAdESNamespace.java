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
package eu.europa.esig.xades.definition;

import eu.europa.esig.dss.jaxb.common.definition.DSSNamespace;

/**
 * Defines a list of used XAdES namespaces
 */
public class XAdESNamespace {

	/** The XMLDSIG Filter 2.0 namespace */
	public static final DSSNamespace XMLDSIG_FILTER2 = new DSSNamespace("http://www.w3.org/2002/06/xmldsig-filter2", "dsig-filter2");

	/** XAdES 1.1.1 */
	public static final DSSNamespace XADES_111 = new DSSNamespace("http://uri.etsi.org/01903/v1.1.1#", "xades111");

	/** XAdES 1.2.2 */
	public static final DSSNamespace XADES_122 = new DSSNamespace("http://uri.etsi.org/01903/v1.2.2#", "xades122");

	/** XAdES 1.3.2 */
	public static final DSSNamespace XADES_132 = new DSSNamespace("http://uri.etsi.org/01903/v1.3.2#", "xades132");

	/** XAdES 1.4.1 */
	public static final DSSNamespace XADES_141 = new DSSNamespace("http://uri.etsi.org/01903/v1.4.1#", "xades141");

	/** XAdES EN 1.1.1 (Evidence record) */
	public static final DSSNamespace XADES_EN = new DSSNamespace("http://uri.etsi.org/19132/v1.1.1# ", "xadesen");

	/**
	 * Empty constructor
	 */
	private XAdESNamespace() {
		// empty
	}

}
