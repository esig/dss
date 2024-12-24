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
package eu.europa.esig.dss.enumerations;

/**
 * ETSI EN 319 412-1 V1.1.1
 * 
 * -- Semantics identifiers
 * 
 * id-etsi-qcs-semantics-identifiers OBJECT IDENTIFIER ::= { itu-t(0)
 * identified-organization(4) etsi(0) id-cert-profile(194121) 1 }
 * 
 */
public enum SemanticsIdentifier implements OidDescription {

	/**
	 * -- Semantics identifier for natural person identifier
	 *
	 * id-etsi-qcs-semanticsId-Natural OBJECT IDENTIFIER ::= {
	 * id-etsi-qcs-semantics-identifiers 1 }
	 */
	qcsSemanticsIdNatural("qcs-semanticsId-Natural", "0.4.0.194121.1.1", "Semantics identifier for natural person"),

	/**
	 * -- Semantics identifier for legal person identifier
	 *
	 * id-etsi-qcs-SemanticsId-Legal OBJECT IDENTIFIER ::= {
	 * id-etsi-qcs-semantics-identifiers 2 }
	 */
	qcsSemanticsIdLegal("qcs-SemanticsId-Legal", "0.4.0.194121.1.2", "Semantics identifier for legal person"),

	/**
	 * -- Semantics identifier for eIDAS natural person identifier
	 *
	 * id-etsi-qcs-semanticsId-eIDASNatural OBJECT IDENTIFIER ::= {
	 * id-etsi-qcs-semantics-identifiers 3 }
	 */
	qcsSemanticsIdEIDASNatural("qcs-semanticsId-eIDASNatural", "0.4.0.194121.1.3", "Semantics identifier for eIDAS natural person"),

	/**
	 * -- Semantics identifier for eIDAS legal person identifier
	 *
	 * id-etsi-qcs-semanticsId-eIDASNatural OBJECT IDENTIFIER ::= {
	 * id-etsi-qcs-semantics-identifiers 4 }
	 */
	qcsSemanticsIdEIDASLegal("qcs-SemanticsId-eIDASLegal", "0.4.0.194121.1.4", "Semantics identifier for eIDAS legal person");

	/** The semantic identifier id name */
	private final String name;

	/** OID */
	private final String oid;

	/** The human-readable description */
	private final String description;

	/**
	 * Default constructor
	 *
	 * @param name {@link String}
	 * @param oid {@link String}
	 * @param description {@link String}
	 */
	SemanticsIdentifier(String name, String oid, String description) {
		this.name = name;
		this.oid = oid;
		this.description = description;
	}

	/**
	 * Returns the ETSI identifier name
	 *
	 * @return {@link String}
	 */
	public String getName() {
		return name;
	}

	@Override
	public String getOid() {
		return oid;
	}

	@Override
	public String getDescription() {
		return description;
	}

	/**
	 * Returns {@code SemanticsIdentifier} based on the provided identifier name
	 *
	 * @param name {@link String}
	 * @return {@link SemanticsIdentifier} if found by the given identifier name, null otherwise
	 */
	public static SemanticsIdentifier fromName(String name) {
		for (SemanticsIdentifier semanticsIdentifier : SemanticsIdentifier.values()) {
			if (semanticsIdentifier.name.equals(name)) {
				return semanticsIdentifier;
			}
		}
		return null;
	}

	/**
	 * Returns {@code SemanticsIdentifier} based on the provided OID
	 *
	 * @param oid {@link String}
	 * @return {@link SemanticsIdentifier} if found by the given OID, null otherwise
	 */
	public static SemanticsIdentifier fromOid(String oid) {
		for (SemanticsIdentifier semanticsIdentifier : SemanticsIdentifier.values()) {
			if (semanticsIdentifier.oid.equals(oid)) {
				return semanticsIdentifier;
			}
		}
		return null;
	}

}
