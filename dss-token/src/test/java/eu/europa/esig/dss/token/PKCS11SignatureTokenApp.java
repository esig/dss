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
package eu.europa.esig.dss.token;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;

import java.security.KeyStore.PasswordProtection;
import java.util.Base64;
import java.util.List;

public class PKCS11SignatureTokenApp {

	public static void main(String[] args) {
		String pin = "PINCODE";

		// -Djava.security.debug = sunpkcs11

		// 32b
		// Pkcs11SignatureToken token = new Pkcs11SignatureToken("C:\\Windows\\SysWOW64\\onepin-opensc-pkcs11.dll");

		// 64b
		// Pkcs11SignatureToken token = new Pkcs11SignatureToken("C:\\Windows\\System32\\beidpkcs11.dll");
		// Pkcs11SignatureToken token = new Pkcs11SignatureToken("C:\\Windows\\System32\\beidpkcs11.dll",
		// (PasswordInputCallback) null, 3)

		// Pkcs11SignatureToken token = new Pkcs11SignatureToken("C:\\Windows\\System32\\onepin-opensc-pkcs11.dll",
		// new PasswordProtection(PIN.toCharArray()), 1)
		String alias;
		try (Pkcs11SignatureToken token = new Pkcs11SignatureToken("C:\\Program Files\\Gemalto\\Classic Client\\BIN\\gclib.dll",
				new PasswordProtection(pin.toCharArray()), 2)) {

			List<DSSPrivateKeyEntry> keys = token.getKeys();
			for (DSSPrivateKeyEntry entry : keys) {
				System.out.println(entry.getCertificate().getCertificate());
			}

			alias = ((KSPrivateKeyEntry) keys.get(0)).getAlias();

			// ToBeSigned toBeSigned = new ToBeSigned("Hello world".getBytes());
			// SignatureValue signatureValue = token.sign(toBeSigned, DigestAlgorithm.SHA256, dssPrivateKeyEntry);
			// System.out.println("Signature value : " +
			// DatatypeConverter.printBase64Binary(signatureValue.getValue()));
		}

		try (Pkcs11SignatureToken token = new Pkcs11SignatureToken("C:\\Program Files\\Gemalto\\Classic Client\\BIN\\gclib.dll",
				new PasswordProtection(pin.toCharArray()), 2)) {

			DSSPrivateKeyEntry key = token.getKey(alias, new PasswordProtection(pin.toCharArray()));

			ToBeSigned toBeSigned = new ToBeSigned("Hello world".getBytes());
			SignatureValue signatureValue = token.sign(toBeSigned, DigestAlgorithm.SHA256, key);

			System.out.println("Signature value : " + Base64.getEncoder().encodeToString(signatureValue.getValue()));
		}
	}

}
