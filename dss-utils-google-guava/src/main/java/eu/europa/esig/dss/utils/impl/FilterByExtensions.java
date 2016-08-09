package eu.europa.esig.dss.utils.impl;

import java.io.File;

import com.google.common.base.Predicate;

public class FilterByExtensions implements Predicate<File> {

	private final String[] extensions;

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
