package eu.europa.esig.dss.web.interceptor;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.servlet.handler.HandlerInterceptorAdapter;

import eu.europa.esig.dss.tsl.service.TSLRepository;

public class WebappInterceptor extends HandlerInterceptorAdapter {

	@Autowired
	private TSLRepository tslRepository;

	@Override
	public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {

		request.setAttribute("lotlOK", tslRepository.isOk());

		return true;
	}

}
