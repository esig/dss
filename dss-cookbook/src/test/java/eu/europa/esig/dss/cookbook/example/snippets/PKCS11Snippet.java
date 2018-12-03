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
package eu.europa.esig.dss.cookbook.example.snippets;

import java.util.List;

import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.SignatureValue;
import eu.europa.esig.dss.ToBeSigned;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.Pkcs11SignatureToken;
import eu.europa.esig.dss.utils.Utils;

public class PKCS11Snippet {

	public static void main(String[] args) {

		// tag::demo[]

		try (Pkcs11SignatureToken token = new Pkcs11SignatureToken("C:\\Windows\\System32\\beidpkcs11.dll")) {

			List<DSSPrivateKeyEntry> keys = token.getKeys();
			for (DSSPrivateKeyEntry entry : keys) {
				System.out.println(entry.getCertificate().getCertificate());
			}

			ToBeSigned toBeSigned = new ToBeSigned("Hello world".getBytes());
			SignatureValue signatureValue = token.sign(toBeSigned, DigestAlgorithm.SHA256, keys.get(0));

			System.out.println("Signature value : " + Utils.toBase64(signatureValue.getValue()));
		}

		// end::demo[]
	}

}
