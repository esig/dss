package eu.europa.esig.dss.xades;

public class XMLDSigPaths extends AbstractPaths {

	public static final String SIGNATURE_PATH = fromCurrentPosition(XMLDSigElement.SIGNATURE);

	public static final String ALL_SIGNATURES_PATH = getAll(XMLDSigElement.SIGNATURE);

	// ----------------------- From ds:Signature

	public static final String OBJECT_PATH = fromCurrentPosition(XMLDSigElement.OBJECT);

	public static final String MANIFEST_PATH = fromCurrentPosition(XMLDSigElement.OBJECT, XMLDSigElement.MANIFEST);

	public static final String SIGNED_INFO_PATH = fromCurrentPosition(XMLDSigElement.SIGNED_INFO);

	public static final String SIGNATURE_METHOD_PATH = fromCurrentPosition(XMLDSigElement.SIGNED_INFO, XMLDSigElement.SIGNATURE_METHOD);

	public static final String REFERENCE_PATH = fromCurrentPosition(XMLDSigElement.SIGNED_INFO, XMLDSigElement.REFERENCE);

	public static final String SIGNATURE_VALUE_PATH = fromCurrentPosition(XMLDSigElement.SIGNATURE_VALUE);

	public static final String KEY_INFO_PATH = fromCurrentPosition(XMLDSigElement.KEY_INFO);

	public static final String KEY_INFO_X509_CERTIFICATE_PATH = fromCurrentPosition(XMLDSigElement.KEY_INFO, XMLDSigElement.X509_DATA,
			XMLDSigElement.X509_CERTIFICATE);

}
