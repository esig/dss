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

import eu.europa.esig.dss.exception.IllegalInputException;
import eu.europa.esig.dss.pades.validation.ByteRange;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class ByteRangeTest {

	@Test
	public void validateByteRangeTest() {
		ByteRange byteRangeOk = new ByteRange(new int[] { 0, 1280, 2400, 480 });
		byteRangeOk.validate();
	}

	@Test
	public void startNotCover() {
		ByteRange byteRange = new ByteRange(new int[] { 1, 1280, 2400, 480 });
		Exception exception = assertThrows(IllegalInputException.class, () -> byteRange.validate());
		assertEquals("The ByteRange must cover start of file", exception.getMessage());
	}

	@Test
	public void emptyFirstPart() {
		ByteRange byteRange = new ByteRange(new int[] { 0, -1, 240, 480 });
		Exception exception = assertThrows(IllegalInputException.class, () -> byteRange.validate());
		assertEquals("The first hash part doesn't cover anything", exception.getMessage());
	}

	@Test
	public void secondAfterFirst() {
		ByteRange byteRange = new ByteRange(new int[] { 0, 1280, 240, 480 });
		Exception exception = assertThrows(IllegalInputException.class, () -> byteRange.validate());
		assertEquals("The second hash part must start after the first hash part", exception.getMessage());
	}

	@Test
	public void emptySecondPart() {
		ByteRange byteRange = new ByteRange(new int[] { 0, 1280, 2400, -1 });
		Exception exception = assertThrows(IllegalInputException.class, () -> byteRange.validate());
		assertEquals("The second hash part doesn't cover anything", exception.getMessage());
	}

	@Test
	public void wrongSize() {
		ByteRange byteRange = new ByteRange(new int[] { 0 });
		Exception exception = assertThrows(IllegalInputException.class, () -> byteRange.validate());
		assertEquals("Incorrect ByteRange size", exception.getMessage());
	}

	@Test
	public void wrongSize2() {
		ByteRange byteRange = new ByteRange(new int[0]);
		Exception exception = assertThrows(IllegalInputException.class, () -> byteRange.validate());
		assertEquals("Incorrect ByteRange size", exception.getMessage());
	}

}
