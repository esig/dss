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
package eu.europa.esig.dss.pdf;

import java.io.Serializable;
import java.util.Arrays;
import java.util.Comparator;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.model.DSSException;

/**
 * This comparator is used to sort signatures by ByteRange
 */
public class PdfRevisionComparator implements Comparator<PdfRevision>, Serializable {

	private static final long serialVersionUID = 1451660656464810618L;

	private static final Logger LOG = LoggerFactory.getLogger(PdfRevisionComparator.class);

	@Override
	public int compare(PdfRevision o1, PdfRevision o2) {
		/*
		[0, 91747, 124517, 723]
		[0, 126092, 158862, 626]
		[0, 160367, 193137, 642]
		 */
		int[] byteRange1 = o1.getSignatureByteRange();
		int[] byteRange2 = o2.getSignatureByteRange();

		int begin1 = byteRange1[0];
		int begin2 = byteRange2[0];

		// length = (before signature value) + (signature value) + (after signature value)
		int length1 = (byteRange1[1] - byteRange1[0]) + (byteRange1[2] - byteRange1[1]) + byteRange1[3];
		int length2 = (byteRange2[1] - byteRange2[0]) + (byteRange2[2] - byteRange2[1]) + byteRange2[3];

		int end1 = byteRange1[1];
		int end2 = byteRange2[1];

		if ((begin1 >= begin2) && (length1 < end2)) {
			// 1st byterange envelops the whole 2nd byterange
			return -1;
		} else if ((begin2 >= begin1) && (length2 < end1)) {
			// 2nd byterange envelops the whole 1st byterange
			return 1;
		} else if (Arrays.equals(byteRange1, byteRange2)) {
			LOG.warn("More than one signature with the same byte range !");
			return o1.getSigningDate().compareTo(o2.getSigningDate());
		} else {
			throw new DSSException("Strange byte ranges (" + Arrays.toString(byteRange1) + " / " + Arrays.toString(byteRange2) + ")");
		}
	}

}
