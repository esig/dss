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
package eu.europa.esig.dss.ws.converter;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.ws.dto.DigestDTO;
import eu.europa.esig.dss.ws.dto.SignatureValueDTO;
import eu.europa.esig.dss.ws.dto.ToBeSignedDTO;
import org.junit.jupiter.api.Test;


import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

class DTOConverterTest {
	
	@Test
	void toToBeSignedTest() {
		ToBeSignedDTO toBeSignedDTO = new ToBeSignedDTO(new byte[] {'1','2','3'});
		ToBeSigned toBeSigned = DTOConverter.toToBeSigned(toBeSignedDTO);
        assertArrayEquals(toBeSignedDTO.getBytes(), toBeSigned.getBytes());
		assertEquals(toBeSignedDTO.hashCode(), toBeSigned.hashCode());
	}
	
	@Test
	void toToBeSignedNullByteArrayTest() {
		ToBeSignedDTO toBeSignedDTO = new ToBeSignedDTO(null);
		ToBeSigned toBeSigned = DTOConverter.toToBeSigned(toBeSignedDTO);
		assertArrayEquals(toBeSignedDTO.getBytes(), toBeSigned.getBytes());
		assertEquals(toBeSignedDTO.hashCode(), toBeSigned.hashCode());
	}
	
	@Test
	void toToBeSignedNullTest() {
		ToBeSigned toBeSigned = DTOConverter.toToBeSigned(null);
		assertNull(toBeSigned);
	}
	
	@Test
	void toToBeSignedDTOTest() {
		ToBeSigned toBeSigned = new ToBeSigned(new byte[] {'1','2','3'});
		ToBeSignedDTO toBeSignedDTO = DTOConverter.toToBeSignedDTO(toBeSigned);
		assertArrayEquals(toBeSignedDTO.getBytes(), toBeSigned.getBytes());
		assertEquals(toBeSignedDTO.hashCode(), toBeSigned.hashCode());
	}
	
	@Test
	void toSignatureValueTest() {
		SignatureValueDTO signatureValueDTO = new SignatureValueDTO(SignatureAlgorithm.RSA_SHA256,
				Utils.fromBase64("7b907e3ef6f8a4342ba42f9c66518bf32f0ec242e8784284c1d8cd816cd77bf2"));
		SignatureValue signatureValue = DTOConverter.toSignatureValue(signatureValueDTO);
		assertEquals(signatureValueDTO.getAlgorithm(), signatureValue.getAlgorithm());
		assertArrayEquals(signatureValueDTO.getValue(), signatureValue.getValue());
		assertEquals(signatureValueDTO.hashCode(), signatureValue.hashCode());
	}
	
	@Test
	void toSignatureValueDTOTest() {
		SignatureValue signatureValue = new SignatureValue(SignatureAlgorithm.DSA_SHA224, 
				Utils.fromBase64("7b907e3ef6f8a4342ba42f9c66518bf32f0ec242e8784284c1d8cd816cd77bf2"));
		SignatureValueDTO signatureValueDTO = DTOConverter.toSignatureValueDTO(signatureValue);
		assertEquals(signatureValueDTO.getAlgorithm(), signatureValue.getAlgorithm());
		assertArrayEquals(signatureValueDTO.getValue(), signatureValue.getValue());
		assertEquals(signatureValueDTO.hashCode(), signatureValue.hashCode());
	}
	
	@Test
	void toSignatureValueNullArrayTest() {
		SignatureValueDTO signatureValueDTO = new SignatureValueDTO(SignatureAlgorithm.RSA_SHA256, null);
		SignatureValue signatureValue = DTOConverter.toSignatureValue(signatureValueDTO);
		assertEquals(signatureValueDTO.getAlgorithm(), signatureValue.getAlgorithm());
		assertNull(signatureValueDTO.getValue());
		assertEquals(signatureValueDTO.hashCode(), signatureValue.hashCode());
	}
	
	@Test
	void toSignatureValueNullTest() {
		SignatureValue signatureValue = DTOConverter.toSignatureValue(null);
		assertNull(signatureValue);
	}
	
	@Test
	void toDigestTest() {
		DigestDTO digestDTO = new DigestDTO(DigestAlgorithm.SHA1, Utils.fromHex("22BDD97143DF6B39A65AFAD2AF6BD8BF20CD4F7B"));
		Digest digest = DTOConverter.toDigest(digestDTO);
		assertNotNull(digest);
		assertEquals(digest.getAlgorithm(), digestDTO.getAlgorithm());
		assertArrayEquals(digest.getValue(), digestDTO.getValue());
	}
	
	@Test
	void toDigestDTOTest() {
		Digest digest = new Digest(DigestAlgorithm.SHA1, Utils.fromHex("22BDD97143DF6B39A65AFAD2AF6BD8BF20CD4F7B"));
		DigestDTO digestDTO = DTOConverter.toDigestDTO(digest);
		assertNotNull(digestDTO);
		assertEquals(digest.getAlgorithm(), digestDTO.getAlgorithm());
		assertArrayEquals(digest.getValue(), digestDTO.getValue());
	}

}
