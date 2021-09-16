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

import eu.europa.esig.dss.pades.validation.ByteRange;
import eu.europa.esig.dss.pades.validation.PdfSignatureDictionary;
import eu.europa.esig.dss.pdf.PdfSignatureDictionaryComparator;
import eu.europa.esig.dss.pdf.SigFieldPermissions;
import org.bouncycastle.cms.CMSSignedData;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class PdfSignatureDictionaryComparatorTest {
	
    SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd");

	private MockPdfSignatureDictionary mock0;
	private MockPdfSignatureDictionary mock0bis;
	private MockPdfSignatureDictionary mock1;
	private MockPdfSignatureDictionary mock2;
	private MockPdfSignatureDictionary nonZero;
	private MockPdfSignatureDictionary strange1;
	private MockPdfSignatureDictionary strange2;

	@BeforeEach
	public void init() throws ParseException {

		/*
		 * [0, 91747, 124517, 723]
		 * [0, 126092, 158862, 626]
		 * [0, 160367, 193137, 642]
		 */

        mock0 = new MockPdfSignatureDictionary(new int[] { 0, 91747, 124517, 723 }, sdf.parse("2002-01-01"));
        nonZero = new MockPdfSignatureDictionary(new int[] { 40000, 120000, 140000, 500 }); // length = 100 500
		mock1 = new MockPdfSignatureDictionary(new int[] { 0, 126092, 158862, 626 });
		mock2 = new MockPdfSignatureDictionary(new int[] { 0, 160367, 193137, 642 });

        mock0bis = new MockPdfSignatureDictionary(new int[] { 0, 91747, 124517, 723 }, sdf.parse("2004-01-01"));

		strange1 = new MockPdfSignatureDictionary(new int[] { 0, 269649, 298181, 5165 });
		strange2 = new MockPdfSignatureDictionary(new int[] { 0, 300055, 337945, 519 });
	}

	@Test
	public void test1() {
		List<PdfSignatureDictionary> listToSort = new ArrayList<>();

		listToSort.add(mock0);
		listToSort.add(mock1);
		listToSort.add(mock2);

		listToSort.sort(new PdfSignatureDictionaryComparator());

		assertEquals(mock0, listToSort.get(0));
		assertEquals(mock1, listToSort.get(1));
		assertEquals(mock2, listToSort.get(2));

	}

	@Test
	public void test2() {
		List<PdfSignatureDictionary> listToSort = new ArrayList<>();

		listToSort.add(mock2);
		listToSort.add(mock1);
		listToSort.add(mock0);

		listToSort.sort(new PdfSignatureDictionaryComparator());

		assertEquals(mock0, listToSort.get(0));
		assertEquals(mock1, listToSort.get(1));
		assertEquals(mock2, listToSort.get(2));
	}

	@Test
	public void test3() {
		List<PdfSignatureDictionary> listToSort = new ArrayList<>();

		listToSort.add(mock1);
		listToSort.add(mock2);
		listToSort.add(mock0);

		listToSort.sort(new PdfSignatureDictionaryComparator());

		assertEquals(mock0, listToSort.get(0));
		assertEquals(mock1, listToSort.get(1));
		assertEquals(mock2, listToSort.get(2));
	}

	@Test
	public void test4() {
		List<PdfSignatureDictionary> listToSort = new ArrayList<>();
		
		listToSort.add(mock0bis);
		listToSort.add(mock0);

		listToSort.sort(new PdfSignatureDictionaryComparator());
		
		assertEquals(mock0, listToSort.get(0));
		assertEquals(mock0bis, listToSort.get(1));
	}

	@Test
	public void testNotZero() {
		List<PdfSignatureDictionary> listToSort = new ArrayList<>();

		listToSort.add(nonZero);
		listToSort.add(mock0);

		listToSort.sort(new PdfSignatureDictionaryComparator());

		assertEquals(mock0, listToSort.get(0));
		assertEquals(nonZero, listToSort.get(1));
	}

	@Test
	public void testDSS1690() {
		PdfSignatureDictionary sig = new MockPdfSignatureDictionary(new int[] { 0, 6418, 17102, 332 });
		PdfSignatureDictionary archivalTST1 = new MockPdfSignatureDictionary(new int[] { 0, 185123, 191125, 343 });
		PdfSignatureDictionary archivalTST2 = new MockPdfSignatureDictionary(new int[] { 0, 200002, 237892, 637 });

		List<PdfSignatureDictionary> listToSort = Arrays.asList(archivalTST1, sig, archivalTST2);
		listToSort.sort(new PdfSignatureDictionaryComparator());

		assertEquals(sig, listToSort.get(0));
		assertEquals(archivalTST1, listToSort.get(1));
		assertEquals(archivalTST2, listToSort.get(2));
	}

	@Test
	public void testStrange() {
		List<PdfSignatureDictionary> listToSort = new ArrayList<>();

		listToSort.add(strange1);
		listToSort.add(strange2);

		listToSort.sort(new PdfSignatureDictionaryComparator());

		assertEquals(strange1, listToSort.get(0));
		assertEquals(strange2, listToSort.get(1));
	}

	private static class MockPdfSignatureDictionary implements PdfSignatureDictionary {

		private ByteRange byteRange;
        private Date signingDate;

		MockPdfSignatureDictionary(int[] byteRange) {
			this.byteRange = new ByteRange(byteRange);
		}

		MockPdfSignatureDictionary(int[] byteRange, Date signingDate) {
			this.byteRange = new ByteRange(byteRange);
			this.signingDate = signingDate;
		}

		@Override
		public ByteRange getByteRange() {
			return byteRange;
		}

		@Override
		public Date getSigningDate() {
			return signingDate;
		}

		@Override
		public String getSignerName() {
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
		public String getType() {
			return null;
		}

		@Override
		public String getFilter() {
			return null;
		}

		@Override
		public String getSubFilter() {
			return null;
		}

		@Override
		public CertificationPermission getDocMDP() {
			return null;
		}

		@Override
		public SigFieldPermissions getFieldMDP() {
			return null;
		}

		@Override
		public byte[] getContents() {
			return null;
		}

		@Override
		public CMSSignedData getCMSSignedData() {
			return null;
		}

	}

}
