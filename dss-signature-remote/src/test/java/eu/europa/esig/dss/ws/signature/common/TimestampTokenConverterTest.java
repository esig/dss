package eu.europa.esig.dss.ws.signature.common;

import static org.junit.Assert.assertTrue;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.xml.crypto.dsig.CanonicalizationMethod;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.timestamp.TimestampInclude;
import eu.europa.esig.dss.validation.timestamp.TimestampToken;
import eu.europa.esig.dss.ws.dto.TimestampDTO;
import eu.europa.esig.dss.ws.dto.TimestampIncludeDTO;

public class TimestampTokenConverterTest {
	
	private static final String timestampBinaries = "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";
	
	@Test
	public void toTimestampTokenTest() throws Exception {
		TimestampDTO timestampDTO = new TimestampDTO(Utils.fromBase64(timestampBinaries), TimestampType.INDIVIDUAL_DATA_OBJECTS_TIMESTAMP);
		timestampDTO.setCanonicalizationMethod(CanonicalizationMethod.INCLUSIVE);
		timestampDTO.setIncludes(Arrays.asList(new TimestampIncludeDTO("reference-id-1", true)));
		
		TimestampToken timestampToken = TimestampTokenConverter.toTimestampToken(timestampDTO);
		assertNotNull(timestampToken);
		assertEquals(TimestampType.INDIVIDUAL_DATA_OBJECTS_TIMESTAMP, timestampToken.getTimeStampType());
		assertEquals(CanonicalizationMethod.INCLUSIVE, timestampToken.getCanonicalizationMethod());
		assertEquals(1, timestampToken.getTimestampIncludes().size());
		assertEquals("reference-id-1", timestampToken.getTimestampIncludes().get(0).getURI());
		assertTrue(timestampToken.getTimestampIncludes().get(0).isReferencedData());
		assertTrue(Arrays.equals(Utils.fromBase64(timestampBinaries), timestampToken.getEncoded()));
	}
	
	@Test
	public void toTimestampTokenListTest() throws Exception {
		List<TimestampDTO> timestampDTOs = new ArrayList<TimestampDTO>();
		timestampDTOs.add(null);
		timestampDTOs.add(new TimestampDTO());
		timestampDTOs.add(new TimestampDTO(Utils.fromBase64(timestampBinaries), TimestampType.INDIVIDUAL_DATA_OBJECTS_TIMESTAMP));
		
		List<TimestampToken> timestampTokens = TimestampTokenConverter.toTimestampTokens(timestampDTOs);
		assertEquals(1, timestampTokens.size());
		
		TimestampToken timestampToken = timestampTokens.get(0);
		assertNotNull(timestampToken);
		assertEquals(TimestampType.INDIVIDUAL_DATA_OBJECTS_TIMESTAMP, timestampToken.getTimeStampType());
		assertTrue(Arrays.equals(Utils.fromBase64(timestampBinaries), timestampToken.getEncoded()));
	}
	
	@Test
	public void emptyTimestampTokenDTOTest() {
		Exception e = assertThrows(NullPointerException.class, () -> {
			TimestampTokenConverter.toTimestampToken(null);
		});
		assertEquals(e.getMessage(), "TimestampDTO cannot be null!");
		
		e = assertThrows(NullPointerException.class, () -> {
			TimestampTokenConverter.toTimestampToken(new TimestampDTO());
		});
		assertEquals(e.getMessage(), "TimestampDTO binaries cannot be null!");
		
		e = assertThrows(NullPointerException.class, () -> {
			TimestampTokenConverter.toTimestampToken(new TimestampDTO(null, TimestampType.CONTENT_TIMESTAMP));
		});
		assertEquals(e.getMessage(), "TimestampDTO binaries cannot be null!");
		
		e = assertThrows(NullPointerException.class, () -> {
			TimestampTokenConverter.toTimestampToken(new TimestampDTO(Utils.fromBase64(timestampBinaries), null));
		});
		assertEquals(e.getMessage(), "TimestampDTO type cannot be null!");
	}
	
	@Test
	public void wrongBinaryTest() {
		Exception e = assertThrows(DSSException.class, () -> {
			TimestampTokenConverter.toTimestampToken(new TimestampDTO(new byte[] {1, 2, 3}, TimestampType.CONTENT_TIMESTAMP));
		});
		assertTrue(e.getMessage().contains("Cannot convert a TimestampDTO to TimestampToken class"));
	}
	
	@Test
	public void toTimestampDTOTest() throws Exception {
		TimestampToken timestampToken = new TimestampToken(Utils.fromBase64(timestampBinaries), TimestampType.CONTENT_TIMESTAMP);
		assertNotNull(timestampToken);
		timestampToken.setCanonicalizationMethod(CanonicalizationMethod.INCLUSIVE_WITH_COMMENTS);
		timestampToken.setTimestampIncludes(Arrays.asList(new TimestampInclude("reference-id-1", true)));
		
		TimestampDTO timestampDTO = TimestampTokenConverter.toTimestampDTO(timestampToken);
		assertNotNull(timestampDTO);
		assertEquals(timestampToken.getTimeStampType(), timestampDTO.getType());
		assertEquals(timestampToken.getCanonicalizationMethod(), timestampDTO.getCanonicalizationMethod());
		assertEquals(1, timestampDTO.getIncludes().size());
		assertEquals("reference-id-1", timestampDTO.getIncludes().get(0).getURI());
		assertTrue(timestampDTO.getIncludes().get(0).isReferencedData());
		
		assertTrue(Arrays.equals(timestampToken.getEncoded(), timestampDTO.getBinaries()));
	}

}
