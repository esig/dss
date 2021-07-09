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
 * RoleOfPspOid ::= OBJECT IDENTIFIER -- Object Identifier arc for roles of
 * payment service providers -- defined in the present document etsi-psd2-roles
 * OBJECT IDENTIFIER ::={ itu-t(0) identified-organization(4) etsi(0)
 * psd2(19495) id-roles(1) }
 */
public enum RoleOfPspOid implements OidDescription {

	/**
	 * -- Account Servicing Payment Service Provider (PSP_AS) role
	 * id-psd2-role-psp-as OBJECT IDENTIFIER ::= { itu-t(0)
	 * identified-organization(4) etsi(0) psd2(19495) id-roles(1) 1 }
	 */
	PSP_AS("psp-as", "0.4.0.19495.1.1"),

	/**
	 * -- Payment Initiation Service Provider (PSP_PI) role id-psd2-role-psp-pi
	 * OBJECT IDENTIFIER ::= { itu-t(0) identified-organization(4) etsi(0)
	 * psd2(19495) id-roles(1) 2 }
	 */
	PSP_PI("psp-pi", "0.4.0.19495.1.2"),

	/**
	 * -- Account Information Service Provider (PSP_AI) role id-psd2-role-psp-ai
	 * OBJECT IDENTIFIER ::= { itu-t(0) identified-organization(4) etsi(0)
	 * psd2(19495) id-roles(1) 3 }
	 */
	PSP_AI("psp-ai", "0.4.0.19495.1.3"),

	/**
	 * -- Payment Service Provider issuing card-based payment instruments (PSP_IC)
	 * role id-psd2-role-psp-ic OBJECT IDENTIFIER ::= { itu-t(0)
	 * identified-organization(4) etsi(0) psd2(19495) id-roles(1) 4 }
	 */
	PSP_IC("psp-ic", "0.4.0.19495.1.4");

	/** The name of the PSP role */
	private final String description;

	/** The OID of the PSP role */
	private final String oid;

	/**
	 * Default constructor
	 *
	 * @param description {@link String} name
	 * @param oid {@link String}
	 */
	RoleOfPspOid(String description, String oid) {
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

	/**
	 * Returns a {@code RoleOfPspOid} by the given OID
	 *
	 * @param oid {@link String} to get {@link RoleOfPspOid} for
	 * @return {@link RoleOfPspOid}
	 */
	public static RoleOfPspOid fromOid(String oid) {
		for (RoleOfPspOid role : RoleOfPspOid.values()) {
			if (role.oid.equals(oid)) {
				return role;
			}
		}
		return null;
	}

}
