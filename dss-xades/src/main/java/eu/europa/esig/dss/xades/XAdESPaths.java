package eu.europa.esig.dss.xades;

public class XAdESPaths extends AbstractPaths {

	public String getQualifyingPropertiesPath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdESElement.QUALIFYING_PROPERTIES);
	}

	public String getSignedPropertiesPath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdESElement.QUALIFYING_PROPERTIES, XAdESElement.SIGNED_PROPERTIES);
	}

	public String getSignedSignaturePropertiesPath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdESElement.QUALIFYING_PROPERTIES, XAdESElement.SIGNED_PROPERTIES,
				XAdESElement.SIGNED_SIGNATURE_PROPERTIES);
	}

	public String getSigningTimePath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdESElement.QUALIFYING_PROPERTIES, XAdESElement.SIGNED_PROPERTIES,
				XAdESElement.SIGNED_SIGNATURE_PROPERTIES, XAdESElement.SIGNING_TIME);
	}

	public String getSigningCertificatePath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdESElement.QUALIFYING_PROPERTIES, XAdESElement.SIGNED_PROPERTIES,
				XAdESElement.SIGNED_SIGNATURE_PROPERTIES, XAdESElement.SIGNING_CERTIFICATE);
	}

	public String getSigningCertificateV2Path() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdESElement.QUALIFYING_PROPERTIES, XAdESElement.SIGNED_PROPERTIES,
				XAdESElement.SIGNED_SIGNATURE_PROPERTIES, XAdESElement.SIGNING_CERTIFICATE_V2);
	}

	public String getSignatureProductionPlacePath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdESElement.QUALIFYING_PROPERTIES, XAdESElement.SIGNED_PROPERTIES,
				XAdESElement.SIGNED_SIGNATURE_PROPERTIES, XAdESElement.SIGNATURE_PRODUCTION_PLACE);
	}

	public String getSignatureProductionPlaceV2Path() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdESElement.QUALIFYING_PROPERTIES, XAdESElement.SIGNED_PROPERTIES,
				XAdESElement.SIGNED_SIGNATURE_PROPERTIES, XAdESElement.SIGNATURE_PRODUCTION_PLACE_V2);
	}

	public String getSignedDataObjectPropertiesPath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdESElement.QUALIFYING_PROPERTIES, XAdESElement.SIGNED_PROPERTIES,
				XAdESElement.SIGNED_DATA_OBJECT_PROPERTIES);
	}

	public String getUnsignedPropertiesPath() {
		return fromCurrentPosition(XMLDSigElement.OBJECT, XAdESElement.QUALIFYING_PROPERTIES, XAdESElement.UNSIGNED_PROPERTIES);
	}

}
