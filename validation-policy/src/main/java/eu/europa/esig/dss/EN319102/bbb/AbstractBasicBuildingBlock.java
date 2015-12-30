package eu.europa.esig.dss.EN319102.bbb;

import eu.europa.esig.dss.jaxb.detailedreport.XmlAbstractBasicBuildingBlock;

public abstract class AbstractBasicBuildingBlock<T extends XmlAbstractBasicBuildingBlock> {

	protected T result;

	protected ChainItem<T> firstItem;

	public T execute() {
		initChain();
		firstItem.execute();
		return result;
	}

	protected abstract void initChain();

}
