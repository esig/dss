/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * 
 * This file is part of the "DSS - Digital Signature Services" project.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.service;

import java.io.InputStream;
import java.util.Properties;

public abstract class OnlineSourceTest {

    protected static final String ONLINE_PKI_HOST;


    static {
        try (InputStream is = OnlineSourceTest.class.getResourceAsStream("/service.properties")) {
            Properties props = new Properties();
            props.load(is);
            ONLINE_PKI_HOST = props.getProperty("online.pki.host");
        } catch (Exception e) {
            throw new RuntimeException("Unable to initialize from service.properties", e);
        }
    }

}
