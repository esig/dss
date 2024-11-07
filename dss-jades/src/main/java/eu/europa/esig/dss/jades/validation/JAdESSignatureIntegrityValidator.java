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
package eu.europa.esig.dss.jades.validation;

import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.spi.x509.SignatureIntegrityValidator;
import org.jose4j.lang.JoseException;

import java.security.PublicKey;

/**
 * Checks the integrity of a JAdES SignatureValue
 */
public class JAdESSignatureIntegrityValidator extends SignatureIntegrityValidator {

	/** The JWS signature to validate */
	private final JWS jws;

	/**
	 * Default constructor
	 *
	 * @param jws {@link JWS}
	 */
	public JAdESSignatureIntegrityValidator(final JWS jws) {
		this.jws = jws;
	}

	@Override
	protected boolean verify(PublicKey publicKey) throws DSSException {
		try {
			jws.setKey(publicKey);
			return jws.verifySignature();
		} catch (JoseException e) {
			throw new DSSException(e);
		}
	}

}
