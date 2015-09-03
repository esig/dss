package eu.europa.esig.dss.standalone.fx;

import java.io.File;

import javafx.util.StringConverter;

public class FileToStringConverter extends StringConverter<File> {

	@Override
	public String toString(File object) {
		if (object == null){
			return "Select file...";
		}
		return object.getAbsolutePath();
	}

	@Override
	public File fromString(String string) {
		return null;
	}

}
