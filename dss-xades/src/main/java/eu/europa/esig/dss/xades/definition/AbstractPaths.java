package eu.europa.esig.dss.xades.definition;

public abstract class AbstractPaths {

	public static final String all(DSSElement element) {
		return new XPathExpressionBuilder().all().element(element).build();
	}

	public static final String fromCurrentPosition(DSSElement element) {
		return new XPathExpressionBuilder().fromCurrentPosition().element(element).build();
	}

	public static final String allFromCurrentPosition(DSSElement element) {
		return new XPathExpressionBuilder().all().fromCurrentPosition().element(element).build();
	}

	protected static final String all(DSSElement... elements) {
		return new XPathExpressionBuilder().all().elements(elements).build();
	}

	protected static String allNotParent(DSSElement element, DSSElement notParentOf) {
		return new XPathExpressionBuilder().all().element(element).notParentOf(notParentOf).build();
	}

	protected static final String fromCurrentPosition(DSSElement... elements) {
		return new XPathExpressionBuilder().fromCurrentPosition().elements(elements).build();
	}

	protected static final String fromCurrentPosition(DSSElement element, DSSAttribute attribute) {
		return new XPathExpressionBuilder().fromCurrentPosition().element(element).attribute(attribute).build();
	}

}
