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
package eu.europa.esig.dss.test;

import java.security.GeneralSecurityException;
import java.security.Signature;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.SignatureAlgorithm;
import eu.europa.esig.dss.SignatureValue;
import eu.europa.esig.dss.ToBeSigned;
import eu.europa.esig.dss.test.mock.MockPrivateKeyEntry;

public final class TestUtils {

	private TestUtils(){
	}

	public static SignatureValue sign(final SignatureAlgorithm signatureAlgorithm, final MockPrivateKeyEntry privateKey, ToBeSigned bytes) {
		try {
			final Signature signature = Signature.getInstance(signatureAlgorithm.getJCEId());
			signature.initSign(privateKey.getPrivateKey());
			signature.update(bytes.getBytes());
			final byte[] signatureValue = signature.sign();
			return new SignatureValue(signatureAlgorithm, signatureValue);
		} catch (GeneralSecurityException e) {
			throw new DSSException(e);
		}
	}

}
