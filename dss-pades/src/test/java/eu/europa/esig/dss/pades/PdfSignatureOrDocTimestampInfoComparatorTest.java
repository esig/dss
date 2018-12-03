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

import static org.junit.Assert.assertEquals;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Set;

import org.junit.Before;
import org.junit.Test;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.pdf.PdfDssDict;
import eu.europa.esig.dss.pdf.PdfSignatureOrDocTimestampInfo;
import eu.europa.esig.dss.pdf.PdfSignatureOrDocTimestampInfoComparator;

public class PdfSignatureOrDocTimestampInfoComparatorTest {

	private MockPdfSignature mock0;
	private MockPdfSignature strange;
	private MockPdfSignature mock0bis;
	private MockPdfSignature mock1;
	private MockPdfSignature mock2;

	@Before
	public void init() throws ParseException {

		SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd");

		/*
		 * [0, 91747, 124517, 723]
		 * [0, 126092, 158862, 626]
		 * [0, 160367, 193137, 642]
		 */

		mock0 = new MockPdfSignature(new int[] { 0, 91747, 124517, 723 }, sdf.parse("2002-01-01"));
		strange = new MockPdfSignature(new int[] { 40000, 120000, 140000, 500 }); // length = 100 500
		mock1 = new MockPdfSignature(new int[] { 0, 126092, 158862, 626 });
		mock2 = new MockPdfSignature(new int[] { 0, 160367, 193137, 642 });

		mock0bis = new MockPdfSignature(new int[] { 0, 91747, 124517, 723 }, sdf.parse("2004-01-01"));
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
	public void test2() {
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
	public void test3() {
		List<PdfSignatureOrDocTimestampInfo> listToSort = new ArrayList<PdfSignatureOrDocTimestampInfo>();

		listToSort.add(mock1);
		listToSort.add(mock2);
		listToSort.add(mock0);

		Collections.sort(listToSort, new PdfSignatureOrDocTimestampInfoComparator());

		assertEquals(mock0, listToSort.get(0));
		assertEquals(mock1, listToSort.get(1));
		assertEquals(mock2, listToSort.get(2));
	}

	@Test
	public void test4() {
		List<PdfSignatureOrDocTimestampInfo> listToSort = new ArrayList<PdfSignatureOrDocTimestampInfo>();

		listToSort.add(mock0bis);
		listToSort.add(mock0);

		Collections.sort(listToSort, new PdfSignatureOrDocTimestampInfoComparator());

		assertEquals(mock0, listToSort.get(0));
		assertEquals(mock0bis, listToSort.get(1));
	}

	@Test(expected = DSSException.class)
	public void testStrange() {
		List<PdfSignatureOrDocTimestampInfo> listToSort = new ArrayList<PdfSignatureOrDocTimestampInfo>();

		listToSort.add(strange);
		listToSort.add(mock0);

		Collections.sort(listToSort, new PdfSignatureOrDocTimestampInfoComparator());
	}

	private class MockPdfSignature implements PdfSignatureOrDocTimestampInfo {

		private int[] byteRange;
		private Date signingDate;

		MockPdfSignature(int[] byteRange) {
			this(byteRange, null);
		}

		MockPdfSignature(int[] byteRange, Date signingDate) {
			this.byteRange = byteRange;
			this.signingDate = signingDate;
		}

		@Override
		public int[] getSignatureByteRange() {
			return byteRange;
		}

		@Override
		public void checkIntegrity() {
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
			return signingDate;
		}

		@Override
		public byte[] getSignedDocumentBytes() {
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

		@Override
		public byte[] getContent() {
			return null;
		}

		@Override
		public String getFilter() {
			return null;
		}

		@Override
		public boolean isCoverAllOriginalBytes() {
			return false;
		}

	}

}
