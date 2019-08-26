package eu.europa.esig.validationreport.parsers;

import java.util.HashMap;
import java.util.Map;

import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.RevocationReason;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.enumerations.UriBasedEnum;
import eu.europa.esig.validationreport.enums.ConstraintStatus;
import eu.europa.esig.validationreport.enums.ObjectType;
import eu.europa.esig.validationreport.enums.SignatureValidationProcessID;
import eu.europa.esig.validationreport.enums.TypeOfProof;

public final class UriBasedEnumParser {

	private static final Map<String, UriBasedEnum> URI_TO_ENUM_MAP = new HashMap<String, UriBasedEnum>();

	static {
		register(Indication.values());
		register(ObjectType.values());
		register(RevocationReason.values());
		register(SignatureValidationProcessID.values());
		register(SubIndication.values());
		register(TypeOfProof.values());
		register(ConstraintStatus.values());
	}

	private static void register(UriBasedEnum[] values) {
		for (UriBasedEnum uriBasedEnum : values) {
			URI_TO_ENUM_MAP.put(uriBasedEnum.getUri(), uriBasedEnum);
		}
	}

	private UriBasedEnumParser() {
	}

	public static Indication parseMainIndication(String v) {
		return (Indication) parse(v);
	}

	public static ObjectType parseObjectType(String v) {
		return (ObjectType) parse(v);
	}

	public static RevocationReason parseRevocationReason(String v) {
		return (RevocationReason) parse(v);
	}

	public static SignatureValidationProcessID parseSignatureValidationProcessID(String v) {
		return (SignatureValidationProcessID) parse(v);
	}

	public static SubIndication parseSubIndication(String v) {
		return (SubIndication) parse(v);
	}

	public static TypeOfProof parseTypeOfProof(String v) {
		return (TypeOfProof) parse(v);
	}

	public static ConstraintStatus parseConstraintStatus(String v) {
		return (ConstraintStatus) parse(v);
	}

	private static UriBasedEnum parse(String v) {
		if (v != null) {
			return URI_TO_ENUM_MAP.get(v);
		}
		return null;
	}

	public static String print(UriBasedEnum v) {
		if (v != null) {
			return v.getUri();
		}
		return null;
	}

}
