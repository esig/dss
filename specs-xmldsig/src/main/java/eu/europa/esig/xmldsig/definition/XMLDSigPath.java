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
package eu.europa.esig.xmldsig.definition;

import eu.europa.esig.dss.xml.common.definition.AbstractPath;

/**
 * Contains a list of "http://www.w3.org/2000/09/xmldsig#" xpaths
 *
 */
public class XMLDSigPath extends AbstractPath {

	private static final long serialVersionUID = 7404631861282645939L;

	/** The "Type" attribute value for a ds:Reference element referring a "ds:Object" element */
	public static final String OBJECT_TYPE = "http://www.w3.org/2000/09/xmldsig#Object";

	/** The "Type" attribute value for a ds:Reference element referring a signed manifest */
	public static final String MANIFEST_TYPE = "http://www.w3.org/2000/09/xmldsig#Manifest";

	/** The "Type" attribute value for a ds:Reference element a ds:SignatureValue of a counter-signed signature */
	public static final String COUNTER_SIGNATURE_TYPE = "http://uri.etsi.org/01903#CountersignedSignature";

	/** "./ds:Signature" */
	public static final String SIGNATURE_PATH = fromCurrentPosition(XMLDSigElement.SIGNATURE);

	/** "//ds:Signature" */
	public static final String ALL_SIGNATURES_PATH = all(XMLDSigElement.SIGNATURE);

	// ----------------------- From ds:Signature

	/** "./ds:Object" */
	public static final String OBJECT_PATH = fromCurrentPosition(XMLDSigElement.OBJECT);

	/** "./ds:Object/ds:Manifest" */
	public static final String MANIFEST_PATH = fromCurrentPosition(XMLDSigElement.OBJECT, XMLDSigElement.MANIFEST);

	/** "./ds:SignedInfo" */
	public static final String SIGNED_INFO_PATH = fromCurrentPosition(XMLDSigElement.SIGNED_INFO);

	/** "./ds:SignedInfo/ds:CanonicalizationMethod" */
	public static final String SIGNED_INFO_CANONICALIZATION_METHOD = fromCurrentPosition(XMLDSigElement.SIGNED_INFO, XMLDSigElement.CANONICALIZATION_METHOD);

	/** "./ds:SignedInfo/ds:Reference" */
	public static final String SIGNED_INFO_REFERENCE_PATH = fromCurrentPosition(XMLDSigElement.SIGNED_INFO, XMLDSigElement.REFERENCE);

	/** "./ds:SignedInfo/ds:SignatureMethod" */
	public static final String SIGNATURE_METHOD_PATH = fromCurrentPosition(XMLDSigElement.SIGNED_INFO, XMLDSigElement.SIGNATURE_METHOD);

	/** "./ds:Reference" */
	public static final String REFERENCE_PATH = fromCurrentPosition(XMLDSigElement.REFERENCE);

	/** "./ds:SignatureValue" */
	public static final String SIGNATURE_VALUE_PATH = fromCurrentPosition(XMLDSigElement.SIGNATURE_VALUE);

	/** "./ds:SignatureValue/@Id" */
	public static final String SIGNATURE_VALUE_ID_PATH = fromCurrentPosition(XMLDSigElement.SIGNATURE_VALUE, XMLDSigAttribute.ID);
	
	/** "//ds:SignatureValue" */
	public static final String ALL_SIGNATURE_VALUES_PATH = all(XMLDSigElement.SIGNATURE_VALUE);

	/** "./ds:KeyInfo" */
	public static final String KEY_INFO_PATH = fromCurrentPosition(XMLDSigElement.KEY_INFO);

	/** "./ds:KeyInfo/ds:X509Data" */
	public static final String KEY_INFO_X509_DATA = fromCurrentPosition(XMLDSigElement.KEY_INFO, XMLDSigElement.X509_DATA);

	/** "./ds:KeyInfo/ds:X509Data/ds:X509Certificate" */
	public static final String KEY_INFO_X509_CERTIFICATE_PATH = fromCurrentPosition(XMLDSigElement.KEY_INFO, XMLDSigElement.X509_DATA,
			XMLDSigElement.X509_CERTIFICATE);

	/** "./ds:Object/ds:SignatureProperties" */
	public static final String SIGNATURE_PROPERTIES_PATH = fromCurrentPosition(XMLDSigElement.OBJECT, XMLDSigElement.SIGNATURE_PROPERTIES);

	/** "./ds:Object/ds:SignatureProperties/ds:SignatureProperty" */
	public static final String SIGNATURE_PROPERTY_PATH = fromCurrentPosition(XMLDSigElement.OBJECT, XMLDSigElement.SIGNATURE_PROPERTIES,
			XMLDSigElement.SIGNATURE_PROPERTY);

	// ----------------------- For digest

	/** "./ds:DigestMethod/@Algorithm" */
	public static final String DIGEST_METHOD_ALGORITHM_PATH = fromCurrentPosition(XMLDSigElement.DIGEST_METHOD, XMLDSigAttribute.ALGORITHM);

	/** "./ds:DigestValue" */
	public static final String DIGEST_VALUE_PATH = fromCurrentPosition(XMLDSigElement.DIGEST_VALUE);

	// ------------------------- Canonicalization

	/** "./ds:CanonicalizationMethod/@Algorithm" */
	public static final String CANONICALIZATION_ALGORITHM_PATH = fromCurrentPosition(XMLDSigElement.CANONICALIZATION_METHOD, XMLDSigAttribute.ALGORITHM);

	// ------------------------- Transforms

	/** "./ds:Transform" */
	public static final String TRANSFORM_PATH = fromCurrentPosition(XMLDSigElement.TRANSFORM);

	/** "./ds:Transforms" */
	public static final String TRANSFORMS_PATH = fromCurrentPosition(XMLDSigElement.TRANSFORMS);

	/** "./ds:Transforms/ds:Transform" */
	public static final String TRANSFORMS_TRANSFORM_PATH = fromCurrentPosition(XMLDSigElement.TRANSFORMS, XMLDSigElement.TRANSFORM);

	/**
	 * Default constructor
	 */
	public XMLDSigPath() {
		// empty
	}

}
