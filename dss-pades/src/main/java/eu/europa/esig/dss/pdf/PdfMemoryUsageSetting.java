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
 * Represents the PDF document loading setting.
 * NOTE: The setting is applicable only when an instance of {@code eu.europa.esig.dss.model.FileDocument}
 * is provided to the signature creation or validation.
 *
 */
public class PdfMemoryUsageSetting {

	/** The chosen PDF memory usage mode  */
	private final Mode mode;

	/** The maximum number of bytes to be stored in memory */
	private final long maxMemoryBytes;

	/** The maximum number of bytes the in-memory and temporary file may have together */
	private final long maxStorageBytes;

	/**
	 * Default constructor
	 *
	 * @param mode {@link Mode} the memory handling mode
	 */
	protected PdfMemoryUsageSetting(Mode mode) {
		this(mode, -1, -1);
	}

	/**
	 * Constructor with memory allocation parameters
	 *
	 * @param mode {@link Mode} the memory handling mode
	 * @param maxMemoryBytes the maximum number of bytes to be allocated in memory
	 * @param maxStorageBytes the maximum number of bytes to be allocated both in memory and in a temporary file
	 */
	protected PdfMemoryUsageSetting(Mode mode, long maxMemoryBytes, long maxStorageBytes) {
		this.mode = mode;
		this.maxMemoryBytes = maxMemoryBytes;
		this.maxStorageBytes = maxStorageBytes;
	}

	/**
	 * Gets the PDF memory usage mode
	 *
	 * @return MemoryUsageSetting's load option {@link Mode}
	 */
	public Mode getMode() {
		return mode;
	}

	/**
	 * Gets the maximum number of bytes to be allocated in memory.
	 * NOTE: applicable only when mode is {@code Mode.MEMORY} or {@code Mode.MIXED} (implementation dependent)
	 * 
	 * @return max bytes to be loaded into memory
	 */
	public long getMaxMemoryBytes() {
		return maxMemoryBytes;
	}

	/**
	 * Gets the maximum number of bytes to be allocated in both memory and temporary file.
	 * NOTE: applicable only when mode is {@code Mode.FILE} or {@code Mode.MIXED} (implementation dependent)
	 * 
	 * @return max bytes to be loaded into file
	 */
	public long getMaxStorageBytes() {
		return maxStorageBytes;
	}

	/**
	 * It represents a memory-forced type of handling.
	 * When chosen, the File is read and loaded to a byte array before processing.
	 *
	 * @return the PDF document load setting {@link PdfMemoryUsageSetting}
	 */
	public static PdfMemoryUsageSetting memoryFull() {
		return new PdfMemoryUsageSetting(Mode.MEMORY_FULL);
	}

	/**
	 * It represents memory unrestricted allocation size load mode.
	 * When this method is chosen, the file is loaded to the memory, as needed.
	 * 
	 * @return the PDF document load setting {@link PdfMemoryUsageSetting}
	 */
	public static PdfMemoryUsageSetting memoryBuffered() {
		return memoryBuffered(-1);
	}

	/**
	 * It represents memory unrestricted allocation size load mode.
	 * When this method is chosen, the file is loaded to the memory, as needed.
	 * 
	 * @param maxBytes max allocation size
	 * @return the PDF document load setting {@link PdfMemoryUsageSetting}
	 */
	public static PdfMemoryUsageSetting memoryBuffered(long maxBytes) {
		return new PdfMemoryUsageSetting(Mode.MEMORY_BUFFERED, maxBytes, -1);
	}

	/**
	 * It represents file only unrestricted allocation size load mode.
	 * When this method is chosen, the content of a file is stored in a temporary file in filesystem.
	 * 
	 * @return the PDF document load setting {@link PdfMemoryUsageSetting}
	 */
	public static PdfMemoryUsageSetting fileOnly() {
		return fileOnly(-1);
	}

	/**
	 * It represents file only unrestricted allocation size load mode.
	 * When this method is chosen, the content of a file is stored in a temporary file in filesystem.
	 * 
	 * @param maxStorageBytes max allocation size
	 * @return the PDF document load setting {@link PdfMemoryUsageSetting}
	 */
	public static PdfMemoryUsageSetting fileOnly(long maxStorageBytes) {
		return new PdfMemoryUsageSetting(Mode.FILE, -1, maxStorageBytes);
	}

	/**
	 * It represents mixed memory-first unrestricted file allocation size load mode.
	 * When this mode is chosen, the content of file is stored in memory before exceeding of {@code maxMemoryBytes},
	 * and the rest is stored in a temporary file in a filesystem.
	 * 
	 * @param maxMemoryBytes max memory allocation size
	 * @return the PDF document load setting {@link PdfMemoryUsageSetting}
	 */
	public static PdfMemoryUsageSetting mixed(long maxMemoryBytes) {
		return mixed(maxMemoryBytes, -1);
	}

	/**
	 * It represents mixed memory-first restricted file allocation size load mode.
	 * When this mode is chosen, the content of file is stored in memory before exceeding of {@code maxMemoryBytes},
	 * and the rest is stored in a temporary file in a filesystem.
	 * 
	 * @param maxMemoryBytes  max memory allocation size
	 * @param maxStorageBytes max size the memory and temporary file may have together
	 * @return the PDF document load setting {@link PdfMemoryUsageSetting}
	 */
	public static PdfMemoryUsageSetting mixed(long maxMemoryBytes, long maxStorageBytes) {
		return new PdfMemoryUsageSetting(Mode.MIXED, maxMemoryBytes, maxStorageBytes);
	}

	@Override
	public String toString() {
		return String.format("%s[%s, %d, %d]", PdfMemoryUsageSetting.class.getSimpleName(), mode, maxMemoryBytes, maxStorageBytes);
	}

	/**
	 * MemoryUsageSetting's load options
	 */
	public enum Mode {

		/**
		 * Loads File to the memory prior to reading.
		 * This method reads the content of File using FileInputStream and provides binary array into the specific implementation.
		 * NOTE: This method significantly increases memory loading, but may provide performance improvements.
		 */
		MEMORY_FULL,

		/**
		 * Loads the File to the memory during the reading.
		 * This method uses implementation specific in-memory processing (i.e. PdfBox or OpenPdf handling).
		 */
		MEMORY_BUFFERED,

		/**
		 * Connects to the File in filesystem during reading.
		 * This method uses implementation specific in-memory processing (i.e. PdfBox or OpenPdf handling).
		 */
		FILE,

		/**
		 * Loads a portion of File to the memory during the reading, and the rest handles in a temporary file.
		 * This method uses implementation specific in-memory processing (i.e. PdfBox or OpenPdf handling).
		 */
		MIXED

	}

}
