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
package eu.europa.esig.dss.definition.xmldsig;

import eu.europa.esig.dss.definition.AbstractPaths;

public class XMLDSigPaths extends AbstractPaths {

	public static final String OBJECT_TYPE = "http://www.w3.org/2000/09/xmldsig#Object";

	public static final String MANIFEST_TYPE = "http://www.w3.org/2000/09/xmldsig#Manifest";

	public static final String COUNTER_SIGNATURE_TYPE = "http://uri.etsi.org/01903#CountersignedSignature";

	public static final String SIGNATURE_PATH = fromCurrentPosition(XMLDSigElement.SIGNATURE);

	public static final String ALL_SIGNATURES_PATH = all(XMLDSigElement.SIGNATURE);

	// ----------------------- From ds:Signature

	public static final String OBJECT_PATH = fromCurrentPosition(XMLDSigElement.OBJECT);

	public static final String MANIFEST_PATH = fromCurrentPosition(XMLDSigElement.OBJECT, XMLDSigElement.MANIFEST);

	public static final String SIGNED_INFO_PATH = fromCurrentPosition(XMLDSigElement.SIGNED_INFO);

	public static final String SIGNATURE_METHOD_PATH = fromCurrentPosition(XMLDSigElement.SIGNED_INFO, XMLDSigElement.SIGNATURE_METHOD);

	public static final String SIGNED_INFO_REFERENCE_PATH = fromCurrentPosition(XMLDSigElement.SIGNED_INFO, XMLDSigElement.REFERENCE);

	public static final String REFERENCE_PATH = fromCurrentPosition(XMLDSigElement.REFERENCE);

	public static final String SIGNATURE_VALUE_PATH = fromCurrentPosition(XMLDSigElement.SIGNATURE_VALUE);

	public static final String SIGNATURE_VALUE_ID_PATH = fromCurrentPosition(XMLDSigElement.SIGNATURE_VALUE, XMLDSigAttribute.ID);
	
	public static final String ALL_SIGNATURE_VALUES_PATH = all(XMLDSigElement.SIGNATURE_VALUE);

	public static final String KEY_INFO_PATH = fromCurrentPosition(XMLDSigElement.KEY_INFO);

	public static final String KEY_INFO_X509_CERTIFICATE_PATH = fromCurrentPosition(XMLDSigElement.KEY_INFO, XMLDSigElement.X509_DATA,
			XMLDSigElement.X509_CERTIFICATE);

	public static final String SIGNATURE_PROPERTIES_PATH = fromCurrentPosition(XMLDSigElement.OBJECT, XMLDSigElement.SIGNATURE_PROPERTIES);

	public static final String SIGNATURE_PROPERTY_PATH = fromCurrentPosition(XMLDSigElement.OBJECT, XMLDSigElement.SIGNATURE_PROPERTIES,
			XMLDSigElement.SIGNATURE_PROPERTY);

	// ----------------------- For digest

	public static final String DIGEST_METHOD_ALGORITHM_PATH = fromCurrentPosition(XMLDSigElement.DIGEST_METHOD, XMLDSigAttribute.ALGORITHM);

	public static final String DIGEST_VALUE_PATH = fromCurrentPosition(XMLDSigElement.DIGEST_VALUE);

	// ------------------------- Canonicalization

	public static final String CANONICALIZATION_ALGORITHM_PATH = fromCurrentPosition(XMLDSigElement.CANONICALIZATION_METHOD, XMLDSigAttribute.ALGORITHM);

	// ------------------------- Transforms

	public static final String TRANSFORMS_TRANSFORM_PATH = fromCurrentPosition(XMLDSigElement.TRANSFORMS, XMLDSigElement.TRANSFORM);

}
