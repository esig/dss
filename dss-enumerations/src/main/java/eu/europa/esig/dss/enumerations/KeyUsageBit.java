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
 * KeyUsage bit values
 *
 * KeyUsage ::= BIT STRING {
 * 		digitalSignature (0),
 * 		nonRepudiation (1),
 * 		keyEncipherment (2),
 * 		dataEncipherment (3),
 * 		keyAgreement (4),
 * 		keyCertSign (5),
 * 		cRLSign (6),
 * 		encipherOnly (7),
 * 		decipherOnly (8)
 * }
 */
public enum KeyUsageBit {

	DIGITAL_SIGNATURE("digitalSignature",0),

	NON_REPUDIATION("nonRepudiation",1),

	KEY_ENCIPHERMENT("keyEncipherment",2),

	DATA_ENCIPHERMENT("dataEncipherment",3),

	KEY_AGREEMENT("keyAgreement",4),

	KEY_CERT_SIGN("keyCertSign",5),

	CRL_SIGN("crlSign",6),

	ENCIPHER_ONLY("encipherOnly",7),

	DECIPHER_ONLY("decipherOnly",8);

	private final String value;
	private final int index;

	KeyUsageBit(String value, int index) {
		this.value = value;
		this.index = index;
	}

	public String getValue() {
		return value;
	}

	public int getIndex() {
		return index;
	}
	
}
