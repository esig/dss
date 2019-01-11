package eu.europa.esig.dss.pades.signature;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;

import org.apache.pdfbox.cos.COSDictionary;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.form.PDField;
import org.apache.pdfbox.pdmodel.interactive.form.PDSignatureField;
import org.junit.Assert;
import org.junit.Test;

public class TestPdfSigFieldLock {
	@Test
	public void test() throws IOException {
		Path path = Paths.get("C:/Users/davyd.santos/Desktop/Loan.docx_locked.pdf");
		try (InputStream is = Files.newInputStream(path); PDDocument d = PDDocument.load(is)) {
			List<PDSignatureField> fieldTree = d.getSignatureFields();
			
			boolean foundMoreObjects = false;
			PDField lastAllowedField = null;
			for(PDSignatureField field : fieldTree) {
				COSDictionary fieldInfo = field.getCOSObject();
				COSName fieldType = fieldInfo.getCOSName(COSName.FT);
				if (fieldType != null && fieldType.equals(COSName.SIG)) {
					COSDictionary fieldValue = fieldInfo.getCOSDictionary(COSName.V);
					if (lastAllowedField != null) {
						foundMoreObjects = true;
					}
					if (fieldValue == null) {
						continue;
					}

					COSDictionary lockObj = fieldInfo.getCOSDictionary(COSName.getPDFName("Lock"));
					if (lockObj != null && 
						"All".equals(lockObj.getNameAsString("Action")) && 
						1 == lockObj.getInt(COSName.P)) {
						lastAllowedField = field;
					}
				}
			}		
			
			if (lastAllowedField == null) {
				Assert.assertFalse("Found changes after lock signature", foundMoreObjects);
			}
		}
	}
}
