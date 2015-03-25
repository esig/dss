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
package eu.europa.ec.markt.dss.applet.model;

import java.io.File;

import com.jgoodies.binding.beans.Model;

import eu.europa.ec.markt.dss.applet.main.FileType;
import eu.europa.ec.markt.dss.applet.util.FileTypeDetectorUtils;
import eu.europa.ec.markt.dss.ws.signature.SignaturePackaging;

/**
 *
 * TODO
 *
 *
 *
 *
 *
 *
 */
@SuppressWarnings("serial")
public class ExtendSignatureModel extends Model {
	/**
	 *
	 */
	public static final String PROPERTY_SELECTED_FILE = "selectedFile";
	/**
	 *
	 */
	public static final String PROPERTY_ORIGINAL_FILE = "originalFile";
	/**
	 *
	 */
	public static final String PROPERTY_TARGET_FILE = "targetFile";
	/**
	 *
	 */
	public static final String PROPERTY_FORMAT = "format";
	/**
	 *
	 */
	public static final String PROPERTY_LEVEL = "level";
	/**
	 *
	 */
	public static final String PROPERTY_PACKAGING = "packaging";

	private File selectedFile;
	private File originalFile;
	private File targetFile;

	private SignaturePackaging packaging;

	private String format;

	private String level;

	/**
	 * @return the fileType
	 */
	public FileType getFileType() {
		return FileTypeDetectorUtils.resolveFiletype(getSelectedFile());
	}

	/**
	 * @return the format
	 */
	public String getFormat() {
		return format;
	}

	/**
	 * @return the level
	 */
	public String getLevel() {
		return level;
	}

	/**
	 * @return the originalFile
	 */
	public File getOriginalFile() {
		return originalFile;
	}

	/**
	 * @return the packaging
	 */
	public SignaturePackaging getPackaging() {
		return packaging;
	}

	/**
	 * @return the selectedFile
	 */
	public File getSelectedFile() {
		return selectedFile;
	}

	public File getTargetFile() {
		return targetFile;
	}

	/**
	 * @param format the format to set
	 */
	public void setFormat(final String format) {
		final String oldValue = this.format;
		final String newValue = format;
		this.format = newValue;
		firePropertyChange(PROPERTY_FORMAT, oldValue, newValue);
	}

	/**
	 * @param level the level to set
	 */
	public void setLevel(final String level) {
		final String oldValue = this.level;
		final String newValue = level;
		this.level = newValue;
		firePropertyChange(PROPERTY_LEVEL, oldValue, newValue);
	}

	/**
	 * @param originalFile the originalFile to set
	 */
	public void setOriginalFile(final File originalFile) {
		final File oldValue = this.originalFile;
		final File newValue = originalFile;
		this.originalFile = newValue;
		firePropertyChange(PROPERTY_ORIGINAL_FILE, oldValue, newValue);
	}

	/**
	 * @param packaging the packaging to set
	 */
	public void setPackaging(final SignaturePackaging packaging) {
		final SignaturePackaging oldValue = this.packaging;
		final SignaturePackaging newValue = packaging;
		this.packaging = newValue;
		firePropertyChange(PROPERTY_PACKAGING, oldValue, newValue);
	}

	/**
	 * @param selectedFile the selectedFile to set
	 */
	public void setSelectedFile(final File selectedFile) {
		final File oldValue = this.selectedFile;
		final File newValue = selectedFile;
		this.selectedFile = newValue;
		firePropertyChange(PROPERTY_SELECTED_FILE, oldValue, newValue);
	}

	/**
	 *
	 * @param targetFile the target file to set
	 */
	public void setTargetFile(File targetFile) {
		final File oldValue = this.targetFile;
		final File newValue = targetFile;
		this.targetFile = newValue;
		firePropertyChange(PROPERTY_TARGET_FILE, oldValue, newValue);
	}

}
