package eu.europa.esig.dss.pades;

import static org.junit.Assert.assertEquals;

import java.io.FileInputStream;
import java.util.List;

import org.apache.commons.codec.binary.Hex;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.junit.Test;

import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.DigestAlgorithm;

public class VRITest {

	@Test
	public void vri() throws Exception {
		String path = "src/test/resources/plugtest/esig2014/ESIG-PAdES/HU_MIC/Signature-P-HU_MIC-3.pdf";
		String vriValue = "C41B1DBFE0E816D8A6F99A9DB98FD43960A5CF45";

		PDDocument pdDoc = PDDocument.load(new FileInputStream(path));
		List<PDSignature> signatureDictionaries = pdDoc.getSignatureDictionaries();
		PDSignature pdSignature = signatureDictionaries.get(0);
		byte[] contents = pdSignature.getContents(new FileInputStream(path));
		byte[] digest = DSSUtils.digest(DigestAlgorithm.SHA1, contents);
		assertEquals(vriValue, Hex.encodeHexString(digest).toUpperCase());

		// We can't use CMSSignedData, the pdSignature content is trimmed (000000)
	}

}
