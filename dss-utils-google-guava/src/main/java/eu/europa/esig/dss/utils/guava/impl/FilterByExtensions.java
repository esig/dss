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
package eu.europa.esig.dss.utils.guava.impl;

import com.google.common.base.Predicate;

import java.io.File;

/**
 * Filters files by extension
 */
public class FilterByExtensions implements Predicate<File> {

	/** Extensions */
	private final String[] extensions;

	/**
	 * Default constructor
	 *
	 * @param extensions {@link String}s
	 */
	public FilterByExtensions(String[] extensions) {
		this.extensions = extensions;
	}

	@Override
	public boolean apply(File file) {
		for (String extension : extensions) {
			if (file.getName().endsWith(extension)) {
				return true;
			}
		}
		return false;
	}

}
