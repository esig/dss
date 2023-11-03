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
package eu.europa.esig.dss.xades.reference;

import eu.europa.esig.dss.xml.common.definition.DSSNamespace;
import eu.europa.esig.xmldsig.definition.XMLDSigNamespace;

/**
 * The simple enveloped signature transform.
 *
 * WARN: cannot be used with parallel signatures!
 */
public final class XPathEnvelopedSignatureTransform extends XPathTransform {

	private static final long serialVersionUID = 1425638155172234234L;

	/**
	 * This XPath filter allows to remove all ds:Signature elements from the XML
	 */
	private static final String NOT_ANCESTOR_OR_SELF_DS_SIGNATURE = "not(ancestor-or-self::ds:Signature)";

	/**
	 * Default constructor
	 */
	public XPathEnvelopedSignatureTransform() {
		super(XMLDSigNamespace.NS, NOT_ANCESTOR_OR_SELF_DS_SIGNATURE);
	}

	/**
	 * Constructor with namespace
	 *
	 * @param xmlDSigNamespace {@link DSSNamespace}
	 */
	public XPathEnvelopedSignatureTransform(DSSNamespace xmlDSigNamespace) {
		super(xmlDSigNamespace, NOT_ANCESTOR_OR_SELF_DS_SIGNATURE);
	}

}
