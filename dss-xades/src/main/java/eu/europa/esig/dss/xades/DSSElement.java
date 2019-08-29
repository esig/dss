package eu.europa.esig.dss.xades;

public interface DSSElement {

	String getTagName();

	DSSNamespace getNamespace();

	String getURI();

	boolean isSameTagName(String value);

}
