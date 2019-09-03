package eu.europa.esig.dss.xades.definition.xmldsig;

import eu.europa.esig.dss.xades.definition.AbstractPaths;

public class XMLDSigPaths extends AbstractPaths {

	public static final String OBJECT_TYPE = "http://www.w3.org/2000/09/xmldsig#Object";

	public static final String MANIFEST_TYPE = "http://www.w3.org/2000/09/xmldsig#Manifest";

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

	public static final String KEY_INFO_PATH = fromCurrentPosition(XMLDSigElement.KEY_INFO);

	public static final String KEY_INFO_X509_CERTIFICATE_PATH = fromCurrentPosition(XMLDSigElement.KEY_INFO, XMLDSigElement.X509_DATA,
			XMLDSigElement.X509_CERTIFICATE);

	// ----------------------- For digest

	public static final String DIGEST_METHOD_ALGORITHM_PATH = fromCurrentPosition(XMLDSigElement.DIGEST_METHOD, XMLDSigAttribute.ALGORITHM);

	public static final String DIGEST_VALUE_PATH = fromCurrentPosition(XMLDSigElement.DIGEST_VALUE);

	// ------------------------- Canonicalization

	public static final String CANONICALIZATION_ALGORITHM_PATH = fromCurrentPosition(XMLDSigElement.CANONICALIZATION_METHOD, XMLDSigAttribute.ALGORITHM);

	// ------------------------- Transforms

	public static final String TRANSFORMS_TRANSFORM_PATH = fromCurrentPosition(XMLDSigElement.TRANSFORMS, XMLDSigElement.TRANSFORM);

}
