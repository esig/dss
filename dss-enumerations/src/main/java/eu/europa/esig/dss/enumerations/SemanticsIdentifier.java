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
	qcsSemanticsIdNatural("Semantics identifier for natural person", "0.4.0.194121.1.1"),

	/**
	 * -- Semantics identifier for legal person identifier
	 *
	 * id-etsi-qcs-SemanticsId-Legal OBJECT IDENTIFIER ::= {
	 * id-etsi-qcs-semantics-identifiers 2 }
	 */
	qcsSemanticsIdLegal("Semantics identifier for legal person", "0.4.0.194121.1.2");

	/** The human-readable description */
	private final String description;

	/** OID */
	private final String oid;

	/**
	 * Default constructor
	 *
	 * @param description {@link String}
	 * @param oid {@link String}
	 */
	SemanticsIdentifier(String description, String oid) {
		this.description = description;
		this.oid = oid;
	}

	@Override
	public String getDescription() {
		return description;
	}

	@Override
	public String getOid() {
		return oid;
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
