package eu.europa.esig.dss.validation;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import eu.europa.esig.dss.model.DSSException;

/**
 * This class represents a ByteRange of a PDF Revision
 *
 */
public class ByteRange {
	
	private int[] byteRange;
	
	/**
	 * This constructor represents a ByteRange extracted from a Signature Dictionary of a signed/timestamped revision
	 * 
	 * @param byteRange 
	 * 				byte range of a signature/timestamp
	 */
	public ByteRange(int[] byteRange) {
		this.byteRange = byteRange;
	}
	
	/**
	 * Returns a complete revision length
	 * 
	 * @return length
	 */
	public int getLength() {
		// (before signature value) + (signature value) + (after signature value)
		return (byteRange[1] - byteRange[0]) + (byteRange[2] - byteRange[1]) + byteRange[3];
	}
	
	/**
	 * Returns the first byte number of the first part of the revision
	 * 
	 * @return first byte
	 */
	public int getFirstPartStart() {
		return byteRange[0];
	}
	
	/**
	 * Returns the last byte number of the first part of the revision
	 * 
	 * @return first part end byte
	 */
	public int getFirstPartEnd() {
		return byteRange[1];
	}

	/**
	 * Returns the first byte number of the second part of the revision
	 * 
	 * @return second part start byte
	 */
	public int getSecondPartStart() {
		return byteRange[2];
	}

	/**
	 * Returns the last byte number of the second part of the revision
	 * 
	 * @return second part end byte
	 */
	public int getSecondPartEnd() {
		return byteRange[3];
	}

	/**
	 * Transforms the ByteRange to a list of BigIntegers
	 * @return a list of {@link BigInteger}s
	 */
	public List<BigInteger> toBigIntegerList() {
		List<BigInteger> bi = new ArrayList<>();
		for (int i : byteRange) {
			bi.add(BigInteger.valueOf(i));
		}
		return bi;
	}
	
	/**
	 * Checks a validity of the ByteRange according to PDF specifications
	 */
	public void validate() {
		if (byteRange == null || byteRange.length != 4) {
			throw new DSSException("Incorrect ByteRange size");
		}

		final int a = byteRange[0];
		final int b = byteRange[1];
		final int c = byteRange[2];
		final int d = byteRange[3];

		if (a != 0) {
			throw new DSSException("The ByteRange must cover start of file");
		}
		if (b <= 0) {
			throw new DSSException("The first hash part doesn't cover anything");
		}
		if (c <= b) {
			throw new DSSException("The second hash part must start after the first hash part");
		}
		if (d <= 0) {
			throw new DSSException("The second hash part doesn't cover anything");
		}
	}
	
	@Override
	public String toString() {
		return Arrays.toString(byteRange);
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + Arrays.hashCode(byteRange);
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
		if (!Arrays.equals(byteRange, other.byteRange)) {
			return false;
		}
		return true;
	}
	
}
