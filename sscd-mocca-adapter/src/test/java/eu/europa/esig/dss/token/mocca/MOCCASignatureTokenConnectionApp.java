/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * 
 * This file is part of the "DSS - Digital Signature Services" project.
 * 
 * Licensed under the EUPL, Version 1.1 or – as soon they
 * will be approved by the European Commission - subsequent
 * versions of the EUPL (the "Licence");
 * 
 * You may not use this work except in compliance with the
 * Licence.
 * 
 * You may obtain a copy of the Licence at:
 * 
 * https://joinup.ec.europa.eu/software/page/eupl
 * 
 * Unless required by applicable law or agreed to in
 * writing, software distributed under the Licence is
 * distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied.
 * 
 * See the Licence for the specific language governing
 * permissions and limitations under the Licence.
 */
package eu.europa.esig.dss.token.mocca;

import java.security.KeyStore.PasswordProtection;
import java.util.List;

import org.bouncycastle.util.encoders.Base64;

import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.SignatureValue;
import eu.europa.esig.dss.ToBeSigned;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.PrefilledPasswordCallback;

public class MOCCASignatureTokenConnectionApp {

	private static final String PIN_CODE = "PINCODE";

	public static void main(String[] args) {
		try (MOCCASignatureTokenConnection token = new MOCCASignatureTokenConnection(
				new PrefilledPasswordCallback(new PasswordProtection(PIN_CODE.toCharArray())))) {

			List<DSSPrivateKeyEntry> keys = token.getKeys();
			for (DSSPrivateKeyEntry entry : keys) {
				System.out.println(entry.getCertificate().getCertificate());
			}

			ToBeSigned toBeSigned = new ToBeSigned("Hello world".getBytes());
			SignatureValue signatureValue = token.sign(toBeSigned, DigestAlgorithm.SHA1, keys.get(0));
			System.out.println("Signature value : " + Base64.toBase64String(signatureValue.getValue()));
		}
	}

}
