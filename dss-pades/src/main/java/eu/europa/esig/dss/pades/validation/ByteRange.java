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
package eu.europa.esig.dss.pades.validation;

import eu.europa.esig.dss.exception.IllegalInputException;
import eu.europa.esig.dss.spi.DSSUtils;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;

/**
 * This class represents a ByteRange of a PDF Revision
 *
 */
public class ByteRange {

	/** Represents a PDF signature byteRange */
	private final int[] byteRangeArray;

	/** Defined whether /ByteRange is valid (shall be defined by external process) */
	private Boolean valid;
	
	/**
	 * This constructor represents a ByteRange extracted from a Signature Dictionary of a signed/timestamped revision
	 * 
	 * @param byteRangeArray
	 * 				byte range of a signature/timestamp
	 */
	public ByteRange(int[] byteRangeArray) {
		this.byteRangeArray = byteRangeArray;
	}
	
	/**
	 * Returns a total revision length
	 * 
	 * @return length
	 */
	public int getLength() {
		// (before signature value) + (signature value) + (after signature value)
		return (byteRangeArray[1] - byteRangeArray[0]) + (byteRangeArray[2] - byteRangeArray[1]) + byteRangeArray[3];
	}
	
	/**
	 * Returns the first byte number of the first part of the revision
	 * 
	 * @return first byte
	 */
	public int getFirstPartStart() {
		return byteRangeArray[0];
	}
	
	/**
	 * Returns the last byte number of the first part of the revision
	 * 
	 * @return first part end byte
	 */
	public int getFirstPartEnd() {
		return byteRangeArray[1];
	}

	/**
	 * Returns the first byte number of the second part of the revision
	 * 
	 * @return second part start byte
	 */
	public int getSecondPartStart() {
		return byteRangeArray[2];
	}

	/**
	 * Returns the last byte number of the second part of the revision
	 * 
	 * @return second part end byte
	 */
	public int getSecondPartEnd() {
		return byteRangeArray[3];
	}

	/**
	 * Transforms the ByteRange to a list of BigIntegers
	 * @return a list of {@link BigInteger}s
	 */
	public List<BigInteger> toBigIntegerList() {
		return DSSUtils.toBigIntegerList(byteRangeArray);
	}
	
	/**
	 * Returns if the /ByteRange is valid
	 *
	 * @return TRUE if the /ByteRange is valid, FALSE otherwise
	 */
	public boolean isValid() {
		if (valid == null) {
			throw new IllegalStateException("ByteRange validation has not been performed! " +
					"Validate the ByteRange and use setValid(valid) method to provide the result.");
		}
		return valid;
	}

	/**
	 * Sets whether /ByteRange has passed the verification against the PDF document
	 *
	 * @param valid if the /ByteRange is valid
	 */
	public void setValid(boolean valid) {
		this.valid = valid;
	}

	/**
	 * Checks a validity of the ByteRange according to PDF specifications.
	 * This method verifies the array of integers representing the ByteRange itself
	 * without taking into account the PDF document, nor the /Contents octets.
	 *
	 * NOTE : this method throws a {@code IllegalInputException} if an error is encountered and
	 *        does not update the state of the object. Please use {@code setValid(valid)} method to define
	 *        the validity of the ByteRange.
	 */
	public void validate() {
		if (byteRangeArray == null || byteRangeArray.length != 4) {
			throw new IllegalInputException("Incorrect ByteRange size");
		}

		final int a = byteRangeArray[0];
		final int b = byteRangeArray[1];
		final int c = byteRangeArray[2];
		final int d = byteRangeArray[3];

		if (a != 0) {
			throw new IllegalInputException("The ByteRange must cover start of file");
		}
		if (b < 0) {
			throw new IllegalInputException("The first hash part doesn't cover anything");
		}
		if (c < a + b) {
			throw new IllegalInputException("The second hash part must start after the first hash part");
		}
		if (d < 0) {
			throw new IllegalInputException("The second hash part doesn't cover anything");
		}
	}
	
	@Override
	public String toString() {
		return Arrays.toString(byteRangeArray);
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + Arrays.hashCode(byteRangeArray);
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		ByteRange other = (ByteRange) obj;
		if (!Arrays.equals(byteRangeArray, other.byteRangeArray)) {
			return false;
		}
		return true;
	}
	
}
