package eu.europa.esig.dss.pades;

import java.awt.Font;
import java.io.InputStream;

public interface DSSFont {
	
	public Font getJavaFont();
	
	public float getSize();
	
	public void setSize(float size);
	
	public boolean isLogicalFont();
	
	public InputStream getInputStream();
	
	public String getName();

}
