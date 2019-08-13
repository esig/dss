package eu.europa.esig.dss.ws.converter;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;

import org.junit.Test;

import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.ws.dto.SignatureValueDTO;
import eu.europa.esig.dss.ws.dto.ToBeSignedDTO;

public class DTOConverterTest {
	
	@Test
	public void toToBeSignedTest() {
		ToBeSignedDTO toBeSignedDTO = new ToBeSignedDTO(new byte[] {'1','2','3'});
		ToBeSigned toBeSigned = DTOConverter.toToBeSigned(toBeSignedDTO);
		assertTrue(Arrays.equals(toBeSignedDTO.getBytes(), toBeSigned.getBytes()));
		assertEquals(toBeSignedDTO.hashCode(), toBeSigned.hashCode());
	}
	
	@Test
	public void toToBeSignedNullByteArrayTest() {
		ToBeSignedDTO toBeSignedDTO = new ToBeSignedDTO(null);
		ToBeSigned toBeSigned = DTOConverter.toToBeSigned(toBeSignedDTO);
		assertTrue(Arrays.equals(toBeSignedDTO.getBytes(), toBeSigned.getBytes()));
		assertEquals(toBeSignedDTO.hashCode(), toBeSigned.hashCode());
	}
	
	@Test
	public void toToBeSignedNullTest() {
		ToBeSigned toBeSigned = DTOConverter.toToBeSigned(null);
		assertTrue(toBeSigned == null);
	}
	
	@Test
	public void toToBeSignedDTOTest() {
		ToBeSigned toBeSigned = new ToBeSigned(new byte[] {'1','2','3'});
		ToBeSignedDTO toBeSignedDTO = DTOConverter.toToBeSignedDTO(toBeSigned);
		assertTrue(Arrays.equals(toBeSignedDTO.getBytes(), toBeSigned.getBytes()));
		assertEquals(toBeSignedDTO.hashCode(), toBeSigned.hashCode());
	}
	
	@Test
	public void toSignatureValueTest() {
		SignatureValueDTO signatureValueDTO = new SignatureValueDTO(SignatureAlgorithm.RSA_SHA256,
				Utils.fromBase64("7b907e3ef6f8a4342ba42f9c66518bf32f0ec242e8784284c1d8cd816cd77bf2"));
		SignatureValue signatureValue = DTOConverter.toSignatureValue(signatureValueDTO);
		assertEquals(signatureValueDTO.getAlgorithm(), signatureValue.getAlgorithm());
		assertTrue(Arrays.equals(signatureValueDTO.getValue(), signatureValue.getValue()));
		assertEquals(signatureValueDTO.hashCode(), signatureValue.hashCode());
	}
	
	@Test
	public void toSignatureValueDTOTest() {
		SignatureValue signatureValue = new SignatureValue(SignatureAlgorithm.DSA_SHA224, 
				Utils.fromBase64("7b907e3ef6f8a4342ba42f9c66518bf32f0ec242e8784284c1d8cd816cd77bf2"));
		SignatureValueDTO signatureValueDTO = DTOConverter.toSignatureValueDTO(signatureValue);
		assertEquals(signatureValueDTO.getAlgorithm(), signatureValue.getAlgorithm());
		assertTrue(Arrays.equals(signatureValueDTO.getValue(), signatureValue.getValue()));
		assertEquals(signatureValueDTO.hashCode(), signatureValue.hashCode());
	}
	
	@Test
	public void toSignatureValueNullArrayTest() {
		SignatureValueDTO signatureValueDTO = new SignatureValueDTO(SignatureAlgorithm.RSA_SHA256, null);
		SignatureValue signatureValue = DTOConverter.toSignatureValue(signatureValueDTO);
		assertEquals(signatureValueDTO.getAlgorithm(), signatureValue.getAlgorithm());
		assertNull(signatureValueDTO.getValue());
		assertEquals(signatureValueDTO.hashCode(), signatureValue.hashCode());
	}
	
	@Test
	public void toSignatureValueNullTest() {
		SignatureValue signatureValue = DTOConverter.toSignatureValue(null);
		assertNull(signatureValue);
	}

}
