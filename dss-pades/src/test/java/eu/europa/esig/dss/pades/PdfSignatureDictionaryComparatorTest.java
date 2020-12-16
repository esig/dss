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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;

import org.bouncycastle.cms.CMSSignedData;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.pades.validation.PdfSignatureDictionary;
import eu.europa.esig.dss.pdf.PdfSignatureDictionaryComparator;
import eu.europa.esig.dss.validation.ByteRange;

public class PdfSignatureDictionaryComparatorTest {
	
    SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd");

	private MockPdfSignatureDictionary mock0;
	private MockPdfSignatureDictionary mock0bis;
	private MockPdfSignatureDictionary mock1;
	private MockPdfSignatureDictionary mock2;
	private MockPdfSignatureDictionary strange;

	@BeforeEach
	public void init() throws ParseException {

		/*
		 * [0, 91747, 124517, 723]
		 * [0, 126092, 158862, 626]
		 * [0, 160367, 193137, 642]
		 */

        mock0 = new MockPdfSignatureDictionary(new int[] { 0, 91747, 124517, 723 }, sdf.parse("2002-01-01"));
        strange = new MockPdfSignatureDictionary(new int[] { 40000, 120000, 140000, 500 }); // length = 100 500
		mock1 = new MockPdfSignatureDictionary(new int[] { 0, 126092, 158862, 626 });
		mock2 = new MockPdfSignatureDictionary(new int[] { 0, 160367, 193137, 642 });

        mock0bis = new MockPdfSignatureDictionary(new int[] { 0, 91747, 124517, 723 }, sdf.parse("2004-01-01"));
	}

	@Test
	public void test1() {
		List<PdfSignatureDictionary> listToSort = new ArrayList<>();

		listToSort.add(mock0);
		listToSort.add(mock1);
		listToSort.add(mock2);

		Collections.sort(listToSort, new PdfSignatureDictionaryComparator());

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

		Collections.sort(listToSort, new PdfSignatureDictionaryComparator());

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

		Collections.sort(listToSort, new PdfSignatureDictionaryComparator());

		assertEquals(mock0, listToSort.get(0));
		assertEquals(mock1, listToSort.get(1));
		assertEquals(mock2, listToSort.get(2));
	}

	@Test
	public void test4() {
		List<PdfSignatureDictionary> listToSort = new ArrayList<>();
		
		listToSort.add(mock0bis);
		listToSort.add(mock0);

		Collections.sort(listToSort, new PdfSignatureDictionaryComparator());
		
		assertEquals(mock0, listToSort.get(0));
		assertEquals(mock0bis, listToSort.get(1));
	}

	@Test
	public void testNotZero() {
		List<PdfSignatureDictionary> listToSort = new ArrayList<>();

		listToSort.add(strange);
		listToSort.add(mock0);

		PdfSignatureDictionaryComparator pdfSignatureDictionaryComparator = new PdfSignatureDictionaryComparator();

		Exception exception = assertThrows(DSSException.class,
				() -> Collections.sort(listToSort, pdfSignatureDictionaryComparator));
		assertEquals(
				"Strange byte ranges (ByteRange : [0, 91747, 124517, 723] / ByteRange : [40000, 120000, 140000, 500])",
				exception.getMessage());
	}

	@Test
	public void testDSS1690() {
		PdfSignatureDictionary sig = new MockPdfSignatureDictionary(new int[] { 0, 6418, 17102, 332 });
		PdfSignatureDictionary archivalTST1 = new MockPdfSignatureDictionary(new int[] { 0, 185123, 191125, 343 });
		PdfSignatureDictionary archivalTST2 = new MockPdfSignatureDictionary(new int[] { 0, 200002, 237892, 637 });

		List<PdfSignatureDictionary> listToSort = Arrays.asList(archivalTST1, sig, archivalTST2);
		Collections.sort(listToSort, new PdfSignatureDictionaryComparator());

		assertEquals(sig, listToSort.get(0));
		assertEquals(archivalTST1, listToSort.get(1));
		assertEquals(archivalTST2, listToSort.get(2));
	}

	private class MockPdfSignatureDictionary implements PdfSignatureDictionary {

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
		public byte[] getContents() {
			return null;
		}

		@Override
		public CMSSignedData getCMSSignedData() {
			return null;
		}

	}

}
