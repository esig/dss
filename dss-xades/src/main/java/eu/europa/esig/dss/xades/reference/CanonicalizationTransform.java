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

import eu.europa.esig.dss.xml.XMLCanonicalizer;
import eu.europa.esig.dss.jaxb.common.definition.DSSNamespace;
import eu.europa.esig.xmldsig.definition.XMLDSigNamespace;

/**
 * Performs a canonicalization transform on XML NodeSet
 */
public class CanonicalizationTransform extends ComplexTransform {

	private static final long serialVersionUID = 4876071474579456586L;

	/**
	 * Default constructor
	 *
	 * @param canonicalizationAlgorithm {@link String} url
	 */
	public CanonicalizationTransform(String canonicalizationAlgorithm) {
		this(XMLDSigNamespace.NS, canonicalizationAlgorithm);
	}

	/**
	 * Constructor with namespace
	 *
	 * @param xmlDSigNamespace {@link DSSNamespace}
	 * @param canonicalizationAlgorithm {@link String} url
	 */
	public CanonicalizationTransform(DSSNamespace xmlDSigNamespace, String canonicalizationAlgorithm) {
		super(xmlDSigNamespace, canonicalizationAlgorithm);
		if (!XMLCanonicalizer.canCanonicalize(canonicalizationAlgorithm)) {
			throw new UnsupportedOperationException(String.format("The provided canonicalization method [%s] is not supported!",
					canonicalizationAlgorithm));
		}
	}

}
