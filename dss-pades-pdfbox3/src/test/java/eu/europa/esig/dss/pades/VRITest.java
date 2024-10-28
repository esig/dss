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
package eu.europa.esig.dss.pades;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import org.apache.pdfbox.Loader;
import org.apache.pdfbox.io.RandomAccessRead;
import org.apache.pdfbox.io.RandomAccessReadBuffer;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class VRITest {

	@Test
	void vri() throws Exception {
		String path = "/validation/Signature-P-HU_MIC-3.pdf";
		String vriValue = "C41B1DBFE0E816D8A6F99A9DB98FD43960A5CF45";

		try (InputStream is = getClass().getResourceAsStream("/validation/Signature-P-HU_MIC-3.pdf");
			 RandomAccessRead rar = new RandomAccessReadBuffer(is);
			 PDDocument pdDoc = Loader.loadPDF(rar)){

			List<PDSignature> signatureDictionaries = pdDoc.getSignatureDictionaries();
			assertTrue(Utils.isCollectionNotEmpty(signatureDictionaries));
			PDSignature pdSignature = signatureDictionaries.get(0);
			byte[] contents = pdSignature.getContents(getClass().getResourceAsStream(path));
			byte[] digest = DSSUtils.digest(DigestAlgorithm.SHA1, contents);
			assertEquals(vriValue, Utils.upperCase(Utils.toHex(digest)));
		}

		// We can't use CMSSignedData, the pdSignature content is trimmed (000000)
	}

}
