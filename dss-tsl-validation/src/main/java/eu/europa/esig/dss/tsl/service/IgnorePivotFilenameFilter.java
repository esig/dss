package eu.europa.esig.dss.tsl.service;

import java.io.File;
import java.io.FilenameFilter;
import java.util.regex.Pattern;

public class IgnorePivotFilenameFilter implements FilenameFilter {

	private static final Pattern NOT_PIVOT_FILENAME_PATTERN = Pattern.compile("^[A-Z]{2}\\.xml$");

	@Override
	public boolean accept(File dir, String name) {
		return NOT_PIVOT_FILENAME_PATTERN.matcher(name).matches();
	}

}
