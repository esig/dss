package eu.europa.esig.dss.web.interceptor;

import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.collections.CollectionUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.servlet.handler.HandlerInterceptorAdapter;

import eu.europa.esig.dss.tsl.ReloadableTrustedListCertificateSource;
import eu.europa.esig.dss.tsl.TSLSimpleReport;

public class WebappInterceptor extends HandlerInterceptorAdapter {

	@Autowired
	private ReloadableTrustedListCertificateSource reloadableTrustedListCertificateSource;

	@Override
	public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {

		boolean lotlOK = true;
		List<TSLSimpleReport> diagnosticInfo = reloadableTrustedListCertificateSource.getDiagnosticInfo();
		if (CollectionUtils.isNotEmpty(diagnosticInfo)) {
			for (TSLSimpleReport tslSimpleReport : diagnosticInfo) {
				if (!tslSimpleReport.isLoaded() || !tslSimpleReport.isAllCertificatesLoaded()) {
					lotlOK = false;
					break;
				}
			}
		}
		request.setAttribute("lotlOK", lotlOK);

		return true;
	}

}
