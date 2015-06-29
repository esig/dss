package eu.europa.esig.dss.pades;

import static org.junit.Assert.assertEquals;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Set;

import org.junit.Before;
import org.junit.Test;

import eu.europa.esig.dss.pdf.PdfDssDict;
import eu.europa.esig.dss.pdf.PdfSignatureOrDocTimestampInfo;
import eu.europa.esig.dss.pdf.PdfSignatureOrDocTimestampInfoComparator;
import eu.europa.esig.dss.validation.SignatureCryptographicVerification;

public class PdfSignatureOrDocTimestampInfoComparatorTest {

	private MockPdfSignature mock0;
	private MockPdfSignature mock1;
	private MockPdfSignature mock2;

	@Before
	public void init() {

		/*
		[0, 91747, 124517, 723]
		[0, 126092, 158862, 626]
		[0, 160367, 193137, 642]
		 */

		mock0 = new MockPdfSignature(new int[] {0, 91747, 124517, 723});
		mock1 = new MockPdfSignature(new int[] {0, 126092, 158862, 626});
		mock2 = new MockPdfSignature(new int[] {0, 160367, 193137, 642});
	}

	@Test
	public void test1() {
		List<PdfSignatureOrDocTimestampInfo> listToSort = new ArrayList<PdfSignatureOrDocTimestampInfo>();

		listToSort.add(mock0);
		listToSort.add(mock1);
		listToSort.add(mock2);

		Collections.sort(listToSort, new PdfSignatureOrDocTimestampInfoComparator());

		assertEquals(mock0, listToSort.get(0));
		assertEquals(mock1, listToSort.get(1));
		assertEquals(mock2, listToSort.get(2));

	}

	@Test
	public void test2(){
		List<PdfSignatureOrDocTimestampInfo> listToSort = new ArrayList<PdfSignatureOrDocTimestampInfo>();

		listToSort.add(mock2);
		listToSort.add(mock1);
		listToSort.add(mock0);

		Collections.sort(listToSort, new PdfSignatureOrDocTimestampInfoComparator());

		assertEquals(mock0, listToSort.get(0));
		assertEquals(mock1, listToSort.get(1));
		assertEquals(mock2, listToSort.get(2));
	}

	@Test
	public void test3(){
		List<PdfSignatureOrDocTimestampInfo> listToSort = new ArrayList<PdfSignatureOrDocTimestampInfo>();

		listToSort.add(mock1);
		listToSort.add(mock2);
		listToSort.add(mock0);

		Collections.sort(listToSort, new PdfSignatureOrDocTimestampInfoComparator());

		assertEquals(mock0, listToSort.get(0));
		assertEquals(mock1, listToSort.get(1));
		assertEquals(mock2, listToSort.get(2));
	}

	private class MockPdfSignature implements PdfSignatureOrDocTimestampInfo {

		private int[] byteRange;

		MockPdfSignature(int[] byteRange) {
			this.byteRange = byteRange;
		}

		@Override
		public int[] getSignatureByteRange() {
			return byteRange;
		}

		@Override
		public SignatureCryptographicVerification checkIntegrity() {
			return null;
		}

		@Override
		public String getLocation() {
			return null;
		}

		@Override
		public String getContactInfo() {
			return null;
		}

		@Override
		public String getReason() {
			return null;
		}

		@Override
		public String getSubFilter() {
			return null;
		}

		@Override
		public Date getSigningDate() {
			return null;
		}

		@Override
		public X509Certificate getSigningCertificate() {
			return null;
		}

		@Override
		public byte[] getSignedDocumentBytes() {
			return null;
		}

		@Override
		public byte[] getOriginalBytes() {
			return null;
		}

		@Override
		public PdfDssDict getDssDictionary() {
			return null;
		}

		@Override
		public String uniqueId() {
			return null;
		}

		@Override
		public void addOuterSignature(PdfSignatureOrDocTimestampInfo signatureInfo) {
		}

		@Override
		public Set<PdfSignatureOrDocTimestampInfo> getOuterSignatures() {
			return null;
		}

		@Override
		public boolean isTimestamp() {
			return false;
		}

	}

}