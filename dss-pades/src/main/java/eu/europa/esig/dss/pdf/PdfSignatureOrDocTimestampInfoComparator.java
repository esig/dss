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
import java.util.Comparator;

/**
 * This comparator is used to sort signatures by ByteRange
 */
public class PdfSignatureOrDocTimestampInfoComparator implements Comparator<PdfSignatureOrDocTimestampInfo>, Serializable {

	private static final long serialVersionUID = 1451660656464810618L;

	@Override
	public int compare(PdfSignatureOrDocTimestampInfo o1, PdfSignatureOrDocTimestampInfo o2) {
		/*
		[0, 91747, 124517, 723]
		[0, 126092, 158862, 626]
		[0, 160367, 193137, 642]
		 */
		int[] byteRange1 = o1.getSignatureByteRange();
		int[] byteRange2 = o2.getSignatureByteRange();

		int totalLenght1 = byteRange1[2] + byteRange1[3];
		int signedContentPre = byteRange2[1] - byteRange2[0];

		return totalLenght1 < signedContentPre ? -1 : totalLenght1 == signedContentPre ? 0 : 1;
	}

}