package eu.europa.ec.markt.dss.cookbook.sources;

import java.util.Calendar;

import eu.europa.ec.markt.dss.TSLConstant;
import eu.europa.ec.markt.dss.validation102853.condition.ServiceInfo;

/**
 * TODO
 * <p>
 * DISCLAIMER: Project owner DG-MARKT.
 *
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 * @version $Revision: 1016 $ - $Date: 2011-06-17 15:30:45 +0200 (Fri, 17 Jun 2011) $
 */
public class MockServiceInfo extends ServiceInfo {

	public MockServiceInfo() {

		setTspName("DSS, Mock Office DSS-CA");
		setType(TSLConstant.CA_QC);
		setServiceName("DSS, Mock Service Name");
		setStatus(TSLConstant.SERVICE_STATUS_UNDERSUPERVISION_119612);
		Calendar calendar = Calendar.getInstance();
		calendar.add(Calendar.YEAR, -15);
		setStatusStartDate(calendar.getTime());
		setStatusEndDate(null);
		setTlWellSigned(true);
	}
}
