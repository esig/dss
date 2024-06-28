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
package eu.europa.esig.dss.test.signature;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.SerializableSignatureParameters;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.signature.AbstractSignatureService;
import eu.europa.esig.dss.test.PKIFactoryAccess;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;

class IsValidSignatureValueTest extends PKIFactoryAccess {

	private MockService service = new MockService(getEmptyCertificateVerifier());
	private String signingAlias = null;

	@Test
	void isValidSignatureValue() {
		ToBeSigned correct = new ToBeSigned("Hello".getBytes());
		ToBeSigned wrong = new ToBeSigned("Bye".getBytes());
		ToBeSigned empty = new ToBeSigned(new byte[] {});
		
		signingAlias = GOOD_USER;

		SignatureValue signatureValue = getToken().sign(correct, DigestAlgorithm.SHA256, getPrivateKeyEntry());
		assertTrue(service.isValidSignatureValue(correct, signatureValue, getSigningCert()));
		assertFalse(service.isValidSignatureValue(wrong, signatureValue, getSigningCert()));
		assertFalse(service.isValidSignatureValue(empty, signatureValue, getSigningCert()));

		ToBeSigned emptyToBeSigned = new ToBeSigned();
		SignatureValue emptySignatureValue = new SignatureValue();
		CertificateToken currentSignCert = getSigningCert();
		assertThrows(NullPointerException.class, () -> service.isValidSignatureValue(null, signatureValue, currentSignCert));
		assertThrows(NullPointerException.class, () -> service.isValidSignatureValue(emptyToBeSigned, signatureValue, currentSignCert));
		assertThrows(NullPointerException.class, () -> service.isValidSignatureValue(correct, null, currentSignCert));
		assertThrows(NullPointerException.class, () -> service.isValidSignatureValue(correct, emptySignatureValue, currentSignCert));
		assertThrows(NullPointerException.class, () -> service.isValidSignatureValue(correct, signatureValue, null));

		SignatureAlgorithm originalAlgorithm = signatureValue.getAlgorithm();

		SignatureValue wrongSignatureValue = new SignatureValue(originalAlgorithm, "Hello".getBytes());
		SignatureValue emptySignatureValueBinary = new SignatureValue(originalAlgorithm, new byte[] {});
		assertFalse(service.isValidSignatureValue(correct, wrongSignatureValue, getSigningCert()));
		assertFalse(service.isValidSignatureValue(correct, emptySignatureValueBinary, getSigningCert()));

		signingAlias = EE_GOOD_USER;
		assertFalse(service.isValidSignatureValue(correct, signatureValue, getSigningCert()));

		signingAlias = GOOD_USER;

		signatureValue.setAlgorithm(SignatureAlgorithm.ECDSA_SHA256);
		assertFalse(service.isValidSignatureValue(correct, signatureValue, getSigningCert()));
		signatureValue.setAlgorithm(SignatureAlgorithm.DSA_SHA256);
		assertFalse(service.isValidSignatureValue(correct, signatureValue, getSigningCert()));
		signatureValue.setAlgorithm(SignatureAlgorithm.ED25519);
		assertFalse(service.isValidSignatureValue(correct, signatureValue, getSigningCert()));
	}

	@Override
	protected String getSigningAlias() {
		return signingAlias;
	}

	private static class MockService extends AbstractSignatureService {

		private static final long serialVersionUID = 1L;

		protected MockService(CertificateVerifier certificateVerifier) {
			super(certificateVerifier);
		}

		@Override
		public ToBeSigned getDataToSign(DSSDocument toSignDocument, SerializableSignatureParameters parameters) {
			return null;
		}

		@Override
		public DSSDocument signDocument(DSSDocument toSignDocument, SerializableSignatureParameters parameters, SignatureValue signatureValue) {
			return null;
		}

		@Override
		public DSSDocument extendDocument(DSSDocument toExtendDocument, SerializableSignatureParameters parameters) {
			return null;
		}

		@Override
		public TimestampToken getContentTimestamp(DSSDocument toSignDocument, SerializableSignatureParameters parameters) {
			return null;
		}

	}
}
