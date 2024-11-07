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
package eu.europa.esig.dss.model.identifier;

import java.security.PublicKey;

/**
 * This class is used to obtain a unique id for a Public key and Subject Name combination
 *
 */
public final class EntityIdentifier extends Identifier {

	private static final long serialVersionUID = -3608001942910223023L;

	/**
	 * Constructor with a public key
	 *
	 * @param publicKey {@link PublicKey}
	 * @deprecated since DSS 6.2. Please use a {@code KeyIdentifier(PublicKey publicKey)} instead
	 */
	@Deprecated
	public EntityIdentifier(final PublicKey publicKey) {
		this(new EntityIdentifierBuilder(publicKey, null).buildBinaries());
	}

	/**
	 * Default constructor
	 *
	 * @param binaries binaries used to build a unique identifier
	 */
	public EntityIdentifier(final byte[] binaries) {
		super("EK-", binaries);
	}

}
