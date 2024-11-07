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
package eu.europa.esig.dss.xades.reference;

import eu.europa.esig.dss.xml.common.definition.DSSNamespace;
import eu.europa.esig.dss.xml.common.definition.xmldsig.XMLDSigNamespace;
import org.apache.xml.security.transforms.Transforms;

/**
 * Used for Enveloped Signature
 * Note: must be followed up by a {@link CanonicalizationTransform}
 */
public class EnvelopedSignatureTransform extends AbstractTransform {

	private static final long serialVersionUID = -7029101849592279769L;

	/**
	 * Default constructor
	 */
	public EnvelopedSignatureTransform() {
		super(XMLDSigNamespace.NS, Transforms.TRANSFORM_ENVELOPED_SIGNATURE);
	}

	/**
	 * Constructor with a custom namespace
	 *
	 * @param xmlDSigNamespace {@link DSSNamespace}
	 */
	public EnvelopedSignatureTransform(DSSNamespace xmlDSigNamespace) {
		super(xmlDSigNamespace, Transforms.TRANSFORM_ENVELOPED_SIGNATURE);
	}

	@Override
	public DSSTransformOutput performTransform(DSSTransformOutput transformOutput) {
		// do nothing the new signature is not existing yet
		return transformOutput;
	}

}
