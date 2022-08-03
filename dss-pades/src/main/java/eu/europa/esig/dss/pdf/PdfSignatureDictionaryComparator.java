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

import eu.europa.esig.dss.pades.validation.PdfSignatureDictionary;
import eu.europa.esig.dss.pades.validation.ByteRange;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.Serializable;
import java.util.Comparator;

/**
 * This comparator is used to sort signatures by ByteRange
 */
public class PdfSignatureDictionaryComparator implements Comparator<PdfSignatureDictionary>, Serializable {

	private static final long serialVersionUID = 1451660656464810618L;

	private static final Logger LOG = LoggerFactory.getLogger(PdfSignatureDictionaryComparator.class);

	/**
	 * Default constructor
	 */
	public PdfSignatureDictionaryComparator() {
		// empty
	}

	@Override
	public int compare(PdfSignatureDictionary o1, PdfSignatureDictionary o2) {
		/*
		[0, 91747, 124517, 723]
		[0, 126092, 158862, 626]
		[0, 160367, 193137, 642]
		 */
		ByteRange byteRange1 = o1.getByteRange();
		ByteRange byteRange2 = o2.getByteRange();
		
        int begin1 = byteRange1.getFirstPartStart();
        int begin2 = byteRange2.getFirstPartStart();

		// length = (before signature value) + (signature value) + (after signature value)
		int length1 = byteRange1.getLength();
		int length2 = byteRange2.getLength();

		int end1 = byteRange1.getFirstPartEnd();
		int end2 = byteRange2.getFirstPartEnd();

        if ((begin1 >= begin2) && (length1 < end2)) {
			// 2nd byterange envelops the whole 1st byterange
			return -1;
        } else if ((begin2 >= begin1) && (length2 < end1)) {
			// 1st byterange envelops the whole 2nd byterange
			return 1;
        } else if (byteRange1.equals(byteRange2)) {
            LOG.warn("More than one signature with the same byte range !");
            return o1.getSigningDate().compareTo(o2.getSigningDate());
		} else {
			LOG.warn("Strange byte ranges (ByteRange : {} / ByteRange : {})", byteRange1, byteRange2);
			if (end1 < end2) {
				return -1;
			} else if (end1 > end2) {
				return 1;
			} else {
				return o1.getSigningDate().compareTo(o2.getSigningDate());
			}
		}
	}

}
