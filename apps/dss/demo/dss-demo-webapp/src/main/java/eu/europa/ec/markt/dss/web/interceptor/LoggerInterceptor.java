/*
 * DSS - Digital Signature Services
 *
 * Copyright (C) 2013 European Commission, Directorate-General Internal Market and Services (DG MARKT), B-1049 Bruxelles/Brussel
 *
 * Developed by: 2013 ARHS Developments S.A. (rue Nicolas Bové 2B, L-1253 Luxembourg) http://www.arhs-developments.com
 *
 * This file is part of the "DSS - Digital Signature Services" project.
 *
 * "DSS - Digital Signature Services" is free software: you can redistribute it and/or modify it under the terms of
 * the GNU Lesser General Public License as published by the Free Software Foundation, either version 2.1 of the
 * License, or (at your option) any later version.
 *
 * DSS is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License along with
 * "DSS - Digital Signature Services".  If not, see <http://www.gnu.org/licenses/>.
 */

package eu.europa.ec.markt.dss.web.interceptor;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.web.servlet.handler.HandlerInterceptorAdapter;

/**
 * This interceptor allow to trace controller invocation and rendering process.
 * 
 * @author vanackda
 * 
 */
public class LoggerInterceptor extends HandlerInterceptorAdapter {

    /**
     * 
     * @author vanackda
     * 
     */
    private static enum STATUS {
        /**
		 * 
		 */
        CALL("HTTP CALL"),
        /**
		 * 
		 */
        EXEC("EXECUTE"),
        /**
		 * 
		 */
        PAM("PAM"),
        /**
		 * 
		 */
        RENDERER("RENDERING");
        /**
		 * 
		 */
        private final String displayValue;

        /**
         * Default constructor.
         * 
         * @param displayValue The value to be displayed.
         */
        STATUS(final String displayValue) {
            this.displayValue = displayValue;
        }

        /*
         * (non-Javadoc)
         * 
         * @see java.lang.Enum#toString()
         */
        @Override
        public String toString() {
            return this.displayValue;
        }
    }

    /**
     * The logger interceptor.
     */
    private static final org.slf4j.Logger LOGGER = org.slf4j.LoggerFactory.getLogger(LoggerInterceptor.class);

    /**
     * Get a {@link String} who contains request method (GET/POST) and request path.
     * 
     * @param request The {@link HttpServletRequest}.
     * @return a concatenate {@link String} with {@link HttpServletRequest} informations.
     */
    private String getRequestInfo(final HttpServletRequest request) {
        StringBuffer buffer = new StringBuffer();
        buffer.append("[" + request.getMethod() + "] ");
        buffer.append(request.getRequestURI());
        return buffer.toString();
    }

    /**
     * Get a {@link String} who contains all parameters from {@link HttpServletRequest} .
     * 
     * @param request The {@link HttpServletRequest}.
     * @return a concatenate {@link String} with all parameters.
     */
    private String getRequestParameterInfo(final HttpServletRequest request) {
        StringBuffer buffer = new StringBuffer();
        for (Object key : request.getParameterMap().keySet()) {
            if (key instanceof String) {
                buffer.append(key + "\t -> " + request.getParameter((String) key) + "\t");
            }
        }
        return buffer.toString();

    }


    /*
     * (non-Javadoc)
     * 
     * @see org.springframework.web.servlet.handler.HandlerInterceptorAdapter#preHandle
     * (javax.servlet.http.HttpServletRequest, javax.servlet.http.HttpServletResponse, java.lang.Object)
     */
    @Override
    public final boolean preHandle(final HttpServletRequest request, final HttpServletResponse response, final Object handler) throws Exception {
        LOGGER.info("[{}] - {}", new Object[] { STATUS.CALL, this.getRequestInfo(request) });
        LOGGER.info("[{}] - {}", new Object[] { STATUS.PAM, this.getRequestParameterInfo(request) });
        return super.preHandle(request, response, handler);
    }

}
