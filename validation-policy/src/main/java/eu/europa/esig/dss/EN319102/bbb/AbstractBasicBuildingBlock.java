package eu.europa.esig.dss.EN319102.bbb;

import eu.europa.esig.dss.jaxb.detailedreport.XmlConclusion;
import eu.europa.esig.dss.jaxb.detailedreport.XmlConstraintsConclusion;
import eu.europa.esig.dss.validation.policy.rules.Indication;

public abstract class AbstractBasicBuildingBlock<T extends XmlConstraintsConclusion> {

	protected final T result;

	protected ChainItem<T> firstItem;

	protected AbstractBasicBuildingBlock(T newInstance) {
		this.result = newInstance;
	}

	public T execute() {
		initChain();
		firstItem.execute();
		if(result.getConclusion() == null) {
			XmlConclusion conclusion = new XmlConclusion();
			conclusion.setIndication(Indication.VALID);
			result.setConclusion(conclusion);
		}
		return result;
	}

	protected abstract void initChain();

}
