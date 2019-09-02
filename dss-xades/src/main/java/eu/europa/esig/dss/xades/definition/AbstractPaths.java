package eu.europa.esig.dss.xades.definition;

public abstract class AbstractPaths {

	protected static final String all(DSSElement... elements) {
		return new XPathExpressionBuilder().all().elements(elements).build();
	}

	protected static final String fromCurrentPosition(DSSElement... elements) {
		return new XPathExpressionBuilder().fromCurrentPosition().elements(elements).build();
	}

	protected static final String fromCurrentPosition(DSSElement element, DSSAttribute attribute) {
		return new XPathExpressionBuilder().fromCurrentPosition().element(element).attribute(attribute).build();
	}

}
