package eu.europa.esig.dss.EN319102.bbb;

import eu.europa.esig.dss.jaxb.detailedreport.XmlAbstractBasicBuildingBlock;

public abstract class AbstractBasicBuildingBlock<T extends XmlAbstractBasicBuildingBlock> {

	public abstract void initChain();

	public abstract T execute();

}
