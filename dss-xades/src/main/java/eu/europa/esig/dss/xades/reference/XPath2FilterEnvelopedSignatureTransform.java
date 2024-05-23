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
import eu.europa.esig.dss.xml.common.definition.xmldsig.XMLDSigNamespace;

/**
 * Enveloped signature transformation by Filter 2.0. Excludes all signatures from the XML.
 */
public final class XPath2FilterEnvelopedSignatureTransform extends XPath2FilterTransform {

	private static final long serialVersionUID = -6358451916689562596L;
	
	/** The subtract filter */
	private static final String SUBTRACT_FILTER = "subtract";

	/** All descendant ds:Signature elements */
	private static final String DESCENDANT_SIGNATURE = "/descendant::ds:Signature";

	/**
	 * Default constructor
	 */
	public XPath2FilterEnvelopedSignatureTransform() {
		super(XMLDSigNamespace.NS, DESCENDANT_SIGNATURE, SUBTRACT_FILTER);
	}

	/**
	 * Constructor with namespace
	 *
	 * @param xmlDSigNamespace {@link DSSNamespace}
	 */
	public XPath2FilterEnvelopedSignatureTransform(DSSNamespace xmlDSigNamespace) {
		super(xmlDSigNamespace, DESCENDANT_SIGNATURE, SUBTRACT_FILTER);
	}

}
