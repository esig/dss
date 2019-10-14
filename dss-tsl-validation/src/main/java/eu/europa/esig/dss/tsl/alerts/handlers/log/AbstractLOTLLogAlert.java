package eu.europa.esig.dss.tsl.alerts.handlers.log;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.spi.tsl.LOTLInfo;
import eu.europa.esig.dss.tsl.alerts.AlertHandler;

public abstract class AbstractLOTLLogAlert implements AlertHandler <LOTLInfo> {

	protected static final Logger LOG = LoggerFactory.getLogger(AbstractLOTLLogAlert.class);

}
