package eu.europa.esig.dss.tsl.alerts.handlers.log;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.spi.tsl.TLInfo;
import eu.europa.esig.dss.tsl.alerts.AlertHandler;

public abstract class AbstractTLLogAlert implements AlertHandler <TLInfo> {

	protected static final Logger LOG = LoggerFactory.getLogger(AbstractTLLogAlert.class);

}
