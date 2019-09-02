package eu.europa.esig.dss.xades.definition;

public interface DSSElement {

	String getTagName();

	DSSNamespace getNamespace();

	String getURI();

	boolean isSameTagName(String value);

}
