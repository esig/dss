package eu.europa.esig.dss.EN319102.bbb;

import eu.europa.esig.dss.jaxb.detailedreport.XmlConstraintsConclusion;

public abstract class AbstractBasicBuildingBlock<T extends XmlConstraintsConclusion> {

	protected final T result;

	protected ChainItem<T> firstItem;

	protected AbstractBasicBuildingBlock(T newInstance) {
		this.result = newInstance;
	}

	public T execute() {
		initChain();
		firstItem.execute();
		return result;
	}

	protected abstract void initChain();

}
