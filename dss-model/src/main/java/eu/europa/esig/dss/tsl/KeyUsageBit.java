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
package eu.europa.esig.dss.tsl;

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

	digitalSignature(0),

	nonRepudiation(1),

	keyEncipherment(2),

	dataEncipherment(3),

	keyAgreement(4),

	keyCertSign(5),

	crlSign(6),

	encipherOnly(7),

	decipherOnly(8);

	private final int index;

	/**
	 * The default constructor for KeyUsageBit.
	 */
	private KeyUsageBit(int index) {
		this.index = index;
	}

	public int getIndex() {
		return index;
	}

}