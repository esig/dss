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
import eu.europa.esig.dss.pdf.PdfDssDict;
import eu.europa.esig.dss.pdf.PdfRevision;
import eu.europa.esig.dss.pdf.PdfRevisionComparator;
import eu.europa.esig.dss.validation.PdfSignatureDictionary;

public class PdfRevisionComparatorTest {

	private MockPdfSignature mock0;
	private MockPdfSignature strange;
	private MockPdfSignature mock0bis;
	private MockPdfSignature mock1;
	private MockPdfSignature mock2;

	@BeforeEach
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
		List<PdfRevision> listToSort = new ArrayList<PdfRevision>();

		listToSort.add(mock0);
		listToSort.add(mock1);
		listToSort.add(mock2);

		Collections.sort(listToSort, new PdfRevisionComparator());

		assertEquals(mock0, listToSort.get(0));
		assertEquals(mock1, listToSort.get(1));
		assertEquals(mock2, listToSort.get(2));

	}

	@Test
	public void test2() {
		List<PdfRevision> listToSort = new ArrayList<PdfRevision>();

		listToSort.add(mock2);
		listToSort.add(mock1);
		listToSort.add(mock0);

		Collections.sort(listToSort, new PdfRevisionComparator());

		assertEquals(mock0, listToSort.get(0));
		assertEquals(mock1, listToSort.get(1));
		assertEquals(mock2, listToSort.get(2));
	}

	@Test
	public void test3() {
		List<PdfRevision> listToSort = new ArrayList<PdfRevision>();

		listToSort.add(mock1);
		listToSort.add(mock2);
		listToSort.add(mock0);

		Collections.sort(listToSort, new PdfRevisionComparator());

		assertEquals(mock0, listToSort.get(0));
		assertEquals(mock1, listToSort.get(1));
		assertEquals(mock2, listToSort.get(2));
	}

	@Test
	public void test4() {
		List<PdfRevision> listToSort = new ArrayList<PdfRevision>();

		listToSort.add(mock0bis);
		listToSort.add(mock0);

		Collections.sort(listToSort, new PdfRevisionComparator());

		assertEquals(mock0, listToSort.get(0));
		assertEquals(mock0bis, listToSort.get(1));
	}

	@Test
	public void testStrange() {
		Exception exception = assertThrows(DSSException.class, () -> {
			List<PdfRevision> listToSort = new ArrayList<PdfRevision>();

			listToSort.add(strange);
			listToSort.add(mock0);

			Collections.sort(listToSort, new PdfRevisionComparator());
		});
		assertEquals("Strange byte ranges ([0, 91747, 124517, 723] / [40000, 120000, 140000, 500])", exception.getMessage());
	}

	@Test
	public void testDSS1690() {
		PdfRevision sig = new MockPdfSignature(new int[] { 0, 6418, 17102, 332 });
		PdfRevision archivalTST1 = new MockPdfSignature(new int[] { 0, 185123, 191125, 343 });
		PdfRevision archivalTST2 = new MockPdfSignature(new int[] { 0, 200002, 237892, 637 });

		List<PdfRevision> listToSort = Arrays.asList(archivalTST1, sig, archivalTST2);
		Collections.sort(listToSort, new PdfRevisionComparator());

		assertEquals(sig, listToSort.get(0));
		assertEquals(archivalTST1, listToSort.get(1));
		assertEquals(archivalTST2, listToSort.get(2));
	}

	private class MockPdfSignature implements PdfRevision {

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
		public byte[] getContents() {
			return null;
		}

		@Override
		public void checkIntegrity() {
		}

		@Override
		public int[] getSignatureByteRange() {
			return byteRange;
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
		public void addOuterSignature(PdfRevision signatureInfo) {
		}

		@Override
		public List<PdfRevision> getOuterSignatures() {
			return null;
		}

		@Override
		public boolean isTimestampRevision() {
			return false;
		}

		@Override
		public CMSSignedData getCMSSignedData() {
			return null;
		}

		@Override
		public boolean doesSignatureCoverAllOriginalBytes() {
			return false;
		}

		@Override
		public PdfSignatureDictionary getPdfSigDictInfo() {
			// TODO Auto-generated method stub
			return null;
		}

	}

}
