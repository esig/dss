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
package eu.europa.esig.dss.xades.requirements;

import java.util.Iterator;

import javax.xml.namespace.NamespaceContext;

public class XAdESNamespaceContext implements NamespaceContext {

	@Override
	public String getNamespaceURI(String prefix) {
		if ("xades".equals(prefix)) {
			return "http://uri.etsi.org/01903/v1.3.2#";
		} else if ("xades141".endsWith(prefix)) {
			return "http://uri.etsi.org/01903/v1.4.1#";
		} else if ("ds".equals(prefix)) {
			return "http://www.w3.org/2000/09/xmldsig#";
		}
		// "http://uri.etsi.org/19132/v1.1.1#"
		return null;
	}

	@Override
	public String getPrefix(String namespaceURI) {
		return null;
	}

	@Override
	@SuppressWarnings("rawtypes")
	public Iterator getPrefixes(String namespaceURI) {
		return null;
	}

}
