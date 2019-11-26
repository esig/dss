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

import org.apache.xml.security.transforms.Transforms;
import org.w3c.dom.Node;

import eu.europa.esig.dss.definition.DSSNamespace;
import eu.europa.esig.dss.xades.DSSXMLUtils;

/**
 * Transforms a reference content to its base64 representation
 * 
 * NOTE: Not compatible with:
 * - other transformations;
 * - isEmbed(true) parameter;
 * - Manifest signature;
 * - Enveloped signatures.
 */
public class Base64Transform extends AbstractTransform {

	public Base64Transform() {
		super(Transforms.TRANSFORM_BASE64_DECODE);
	}

	public Base64Transform(DSSNamespace xmlDSigNamespace) {
		super(xmlDSigNamespace, Transforms.TRANSFORM_BASE64_DECODE);
	}

	@Override
	public byte[] getBytesAfterTranformation(Node node) {
		return DSSXMLUtils.serializeNode(node);
	}

}
