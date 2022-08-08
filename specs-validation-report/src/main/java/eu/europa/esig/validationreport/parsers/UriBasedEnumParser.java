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
package eu.europa.esig.validationreport.parsers;

import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.RevocationReason;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.enumerations.UriBasedEnum;
import eu.europa.esig.validationreport.enums.ConstraintStatus;
import eu.europa.esig.validationreport.enums.ObjectType;
import eu.europa.esig.validationreport.enums.SignatureValidationProcessID;
import eu.europa.esig.validationreport.enums.TypeOfProof;

import java.util.HashMap;
import java.util.Map;

/**
 * Parser for different uri-based values
 */
public final class UriBasedEnumParser {

	/** The map of enum values and corresponding URIs */
	private static final Map<String, UriBasedEnum> URI_TO_ENUM_MAP = new HashMap<>();

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
		// empty
	}

	/**
	 * Parses the string value and returns {@code Indication}
	 *
	 * @param v {@link String}
	 * @return {@link Indication}, null if not able to parse
	 */
	public static Indication parseMainIndication(String v) {
		return (Indication) parse(v);
	}

	/**
	 * Parses the string value and returns {@code SubIndication}
	 *
	 * @param v {@link String}
	 * @return {@link SubIndication}, null if not able to parse
	 */
	public static SubIndication parseSubIndication(String v) {
		return (SubIndication) parse(v);
	}

	/**
	 * Parses the string value and returns {@code ObjectType}
	 *
	 * @param v {@link String}
	 * @return {@link ObjectType}, null if not able to parse
	 */
	public static ObjectType parseObjectType(String v) {
		return (ObjectType) parse(v);
	}

	/**
	 * Parses the string value and returns {@code RevocationReason}
	 *
	 * @param v {@link String}
	 * @return {@link RevocationReason}, null if not able to parse
	 */
	public static RevocationReason parseRevocationReason(String v) {
		return (RevocationReason) parse(v);
	}

	/**
	 * Parses the string value and returns {@code SignatureValidationProcessID}
	 *
	 * @param v {@link String}
	 * @return {@link SignatureValidationProcessID}, null if not able to parse
	 */
	public static SignatureValidationProcessID parseSignatureValidationProcessID(String v) {
		return (SignatureValidationProcessID) parse(v);
	}

	/**
	 * Parses the string value and returns {@code TypeOfProof}
	 *
	 * @param v {@link String}
	 * @return {@link TypeOfProof}, null if not able to parse
	 */
	public static TypeOfProof parseTypeOfProof(String v) {
		return (TypeOfProof) parse(v);
	}

	/**
	 * Parses the string value and returns {@code ConstraintStatus}
	 *
	 * @param v {@link String}
	 * @return {@link ConstraintStatus}, null if not able to parse
	 */
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
