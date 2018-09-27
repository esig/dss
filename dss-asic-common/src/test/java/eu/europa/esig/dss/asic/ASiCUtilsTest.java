package eu.europa.esig.dss.asic;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

import eu.europa.esig.dss.ASiCContainerType;
import eu.europa.esig.dss.MimeType;

public class ASiCUtilsTest {

	@Test
	public void getASiCContainerType() {
		MimeType mt = new MimeType();
		mt.setMimeTypeString("application/vnd.etsi.asic-e+zip");
		assertEquals(ASiCContainerType.ASiC_E, ASiCUtils.getASiCContainerType(mt));

		assertEquals(ASiCContainerType.ASiC_E, ASiCUtils.getASiCContainerType(MimeType.ASICE));
	}

	@Test(expected = IllegalArgumentException.class)
	public void getWrongASiCContainerType() {
		MimeType mt = new MimeType();
		mt.setMimeTypeString("application/wrong");
		ASiCUtils.getASiCContainerType(mt);
	}

}
