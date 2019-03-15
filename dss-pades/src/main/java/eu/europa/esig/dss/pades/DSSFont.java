package eu.europa.esig.dss.pades;

import java.awt.Font;
import java.io.InputStream;

public interface DSSFont {
	
	Font getJavaFont();
	
	float getSize();
	
	void setSize(float size);
	
	boolean isLogicalFont();
	
	InputStream getInputStream();
	
	String getName();

}
