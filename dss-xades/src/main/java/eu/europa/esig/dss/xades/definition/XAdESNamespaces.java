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
package eu.europa.esig.dss.xades.definition;

import javax.xml.crypto.dsig.XMLSignature;

import eu.europa.esig.dss.DSSNamespace;
import eu.europa.esig.dss.DomUtils;

public class XAdESNamespaces {

	public static final DSSNamespace XMLDSIG = new DSSNamespace(XMLSignature.XMLNS, "ds");

	public static final DSSNamespace XADES_111 = new DSSNamespace("http://uri.etsi.org/01903/v1.1.1#", "xades111");
	public static final DSSNamespace XADES_122 = new DSSNamespace("http://uri.etsi.org/01903/v1.2.2#", "xades122");
	public static final DSSNamespace XADES_132 = new DSSNamespace("http://uri.etsi.org/01903/v1.3.2#", "xades132");
	public static final DSSNamespace XADES_141 = new DSSNamespace("http://uri.etsi.org/01903/v1.4.1#", "xades141");

	public static void registerNamespaces() {
		DomUtils.registerNamespace(XMLDSIG.getPrefix(), XMLDSIG.getUri());

		DomUtils.registerNamespace(XADES_111.getPrefix(), XADES_111.getUri());
		DomUtils.registerNamespace(XADES_122.getPrefix(), XADES_122.getUri());
		DomUtils.registerNamespace(XADES_132.getPrefix(), XADES_132.getUri());
		DomUtils.registerNamespace(XADES_141.getPrefix(), XADES_141.getUri());
		// DO NOT register "xades"
	}

}
