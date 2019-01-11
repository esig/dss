package eu.europa.esig.dss.pades;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Collection;

import org.junit.Assert;
import org.junit.Test;

import com.lowagie.text.pdf.AcroFields;
import com.lowagie.text.pdf.AcroFields.Item;
import com.lowagie.text.pdf.PdfDictionary;
import com.lowagie.text.pdf.PdfName;
import com.lowagie.text.pdf.PdfReader;

public class TestPdfSigFieldLock {
	@Test
	public void test() throws IOException {
		Path path = Paths.get("C:/Users/davyd.santos/Desktop/Loan.docx_locked.pdf");
		try (InputStream is = Files.newInputStream(path); PdfReader r = new PdfReader(is)) {
			AcroFields af = r.getAcroFields();
			Collection<String> names = af.getSignatureNames();

			int lockRevision = 0;
			int currentRevision = 0;
			int maxRevision = currentRevision;
			for(String sigFieldName : names) {	
				Item fieldItem = af.getFieldItem(sigFieldName);
				PdfDictionary fieldInfo = fieldItem.getValue(0);
				
				
				currentRevision = af.getRevision(sigFieldName);
				maxRevision = maxRevision > currentRevision? maxRevision: currentRevision;

				PdfDictionary lockObj = fieldInfo.getAsDict(PdfName.LOCK);
				if (lockObj != null && 
					new PdfName("All").equals(lockObj.getAsName(PdfName.ACTION)) && 
					lockObj.contains(PdfName.P) && lockObj.getAsNumber(PdfName.P).intValue() == 1) {
					lockRevision = currentRevision;
				}
			}		
			
			if (lockRevision > 0) {
				Assert.assertEquals("Changes detected after lock", maxRevision, lockRevision);
			}
		}
	}
}
