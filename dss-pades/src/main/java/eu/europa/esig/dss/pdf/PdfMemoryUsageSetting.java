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

/**
 * Represents the PDF document loading setting
 */
public class PdfMemoryUsageSetting {

	/**
	 * MemoryUsageSetting's load options
	 */
	public enum Mode {
		MEMORY, FILE, MIXED;
	}

	private Mode mode;
	private Long maxMemoryBytes;
	private Long maxFileBytes;

	/**
	 * 
	 * @return MemoryUsageSetting's load option {@link Mode}
	 */
	public Mode getMode() {
		return mode;
	}

	/**
	 * Meaningful when mode is {@code Mode.MEMORY} or {@code Mode.MIXED}
	 * 
	 * @return max bytes to be loaded into memory
	 */
	public Long getMaxMemoryBytes() {
		return maxMemoryBytes;
	}

	/**
	 * Meaningful when mode is {@code Mode.FILE} or {@code Mode.MIXED}
	 * 
	 * @return max bytes to be loaded into file
	 */
	public Long getMaxFileBytes() {
		return maxFileBytes;
	}

	private PdfMemoryUsageSetting(Mode mode, Long maxMemoryBytes, Long maxFileBytes) {
		this.mode = mode;
		this.maxMemoryBytes = maxMemoryBytes;
		this.maxFileBytes = maxFileBytes;
	}

	/**
	 * It represents memory only unrestricted allocation size load mode.
	 * 
	 * @return the PDF document load setting {@link PdfMemoryUsageSetting}
	 */
	public static PdfMemoryUsageSetting memoryOnly() {
		return new PdfMemoryUsageSetting(Mode.MEMORY, null, null);
	}

	/**
	 * It represents memory only restricted allocation size load mode.
	 * 
	 * @param maxBytes max allocation size
	 * @return the PDF document load setting {@link PdfMemoryUsageSetting}
	 */
	public static PdfMemoryUsageSetting memoryOnly(long maxBytes) {
		return new PdfMemoryUsageSetting(Mode.MEMORY, maxBytes, null);
	}

	/**
	 * It represents file only unrestricted allocation size load mode.
	 * 
	 * @return the PDF document load setting {@link PdfMemoryUsageSetting}
	 */
	public static PdfMemoryUsageSetting fileOnly() {
		return new PdfMemoryUsageSetting(Mode.FILE, null, null);
	}

	/**
	 * It represents file only unrestricted allocation size load mode.
	 * 
	 * @param maxBytes max allocation size
	 * @return the PDF document load setting {@link PdfMemoryUsageSetting}
	 */
	public static PdfMemoryUsageSetting fileOnly(long maxBytes) {
		return new PdfMemoryUsageSetting(Mode.FILE, null, maxBytes);
	}

	/**
	 * It represents mixed memory-first unrestricted file allocation size load mode.
	 * 
	 * @param maxMemoryBytes max memory allocation size
	 * @return the PDF document load setting {@link PdfMemoryUsageSetting}
	 */
	public static PdfMemoryUsageSetting mixed(long maxMemoryBytes) {
		return new PdfMemoryUsageSetting(Mode.MIXED, maxMemoryBytes, null);
	}

	/**
	 * It represents mixed memory-first restricted file allocation size load mode.
	 * 
	 * @param maxMemoryBytes max memory allocation size
	 * @param maxFileBytes   max file allocation size
	 * @return the PDF document load setting {@link PdfMemoryUsageSetting}
	 */
	public static PdfMemoryUsageSetting mixed(long maxMemoryBytes, long maxFileBytes) {
		return new PdfMemoryUsageSetting(Mode.MIXED, maxMemoryBytes, maxFileBytes);
	}

	@Override
	public String toString() {
		return String.format("%s[%s, %d, %d]", PdfMemoryUsageSetting.class.getSimpleName(), mode, maxMemoryBytes, maxFileBytes);
	}
}
