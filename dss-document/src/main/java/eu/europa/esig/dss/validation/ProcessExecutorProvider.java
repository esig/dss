package eu.europa.esig.dss.validation;

import eu.europa.esig.dss.validation.executor.ProcessExecutor;

public interface ProcessExecutorProvider<PE extends ProcessExecutor<?>> {

	/**
	 * This method provides the possibility to set the specific {@code CustomProcessExecutor}
	 *
	 * @param processExecutor
	 */
	void setProcessExecutor(PE processExecutor);
	
}
