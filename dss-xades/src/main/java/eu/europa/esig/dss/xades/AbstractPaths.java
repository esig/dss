package eu.europa.esig.dss.xades;

public abstract class AbstractPaths {

	protected static final String getAll(DSSElement... elements) {
		return new XPathExpressionBuilder().all().elements(elements).build();
	}

	protected static final String fromCurrentPosition(DSSElement... elements) {
		return new XPathExpressionBuilder().fromCurrentPosition().elements(elements).build();
	}

}
