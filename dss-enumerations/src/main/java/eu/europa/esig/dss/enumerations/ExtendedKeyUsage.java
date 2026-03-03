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
 * The KeyPurposeId object.
 * KeyPurposeId ::= OBJECT IDENTIFIER
 *
 * id-kp ::= OBJECT IDENTIFIER { iso(1) identified-organization(3)
 * dod(6) internet(1) security(5) mechanisms(5) pkix(7) 3}
 */
public enum ExtendedKeyUsage implements OidDescription {

	/** serverAuth */
	SERVER_AUTH("serverAuth", "1.3.6.1.5.5.7.3.1"),

	/** clientAuth */
	CLIENT_AUTH("clientAuth", "1.3.6.1.5.5.7.3.2"),

	/** codeSigning */
	CODE_SIGNING("codeSigning", "1.3.6.1.5.5.7.3.3"),

	/** emailProtection */
	EMAIL_PROTECTION("emailProtection", "1.3.6.1.5.5.7.3.4"),

	// 5,6,7 deprecated by RFC4945

	/** timeStamping */
	TIMESTAMPING("timeStamping", "1.3.6.1.5.5.7.3.8"),

	/** ocspSigning */
	OCSP_SIGNING("ocspSigning", "1.3.6.1.5.5.7.3.9"),

	/**
	 * ETSI TS 119 612
	 * -- OID for TSL signing KeyPurposeID for ExtKeyUsageSyntax
	 * id-tsl OBJECT IDENTIFIER { itu-t(0) identified-organization(4)
	 * etsi(0) tsl-specification (2231) }
	 * id-tsl-kp OBJECT IDENTIFIER ::= { id-tsl kp(3) }
	 * id-tsl-kp-tslSigning OBJECT IDENTIFIER ::= { id-tsl-kp tsl-signing(0) }
	 */
	TSL_SIGNING("tslSigning", "0.4.0.2231.3.0"),

	/**
	 * ETSI TS 119 411-5 (Annex A (normative): id-kp-tlsBinding EKU specification)
	 * The following ASN.1 module shall be interpreted using the syntax defined in Recommendation ITU-T X.680 [11]. It
	 * defines the KeyPurposeID id-kp-tls-binding.
	 * <p>
	 *  -- Object Identifier arc for extended Key Usage purpose id-kp-tls-binding
	 *  id-tlsBinding OBJECT IDENTIFIER ::= { itu-t(0) identified-organization(4)
	 *  etsi(0) id-qwacImplementation(194115) tls-binding (1) }
	 *  id-kp-tls-binding OBJECT IDENTIFIER ::= { id-tlsBinding id-kp-tls-binding(0) }
	 */
	TSL_BINDING("tslBinding", "0.4.0.194115.1.0");

	/** ExtendedKeyUsage description */
	private final String description;

	/** ExtendedKeyUsage OID */
	private final String oid;

	/**
	 * Default constructor
	 *
	 * @param description {@link String}
	 * @param oid {@link String}
	 */
	ExtendedKeyUsage(String description, String oid) {
		this.description = description;
		this.oid = oid;
	}

	@Override
	public String getOid() {
		return oid;
	}

	@Override
	public String getDescription() {
		return description;
	}

}
