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
package eu.europa.esig.dss.applet.swing.mvc;


/**
 * TODO
 *
 *
 *
 *
 * @param <C>
 * @param <M>
 *
 *
 */
public abstract class AppletController<C extends AppletCore, M> {

    protected static final org.slf4j.Logger LOG = org.slf4j.LoggerFactory.getLogger(AppletController.class);

    private final C core;

    private final M model;

    /**
     * The default constructor for AppletController.
     *
     * @param core
     * @param model
     */
    protected AppletController(final C core, final M model) {
        this.core = core;
        this.model = model;
    }

    /**
     * @return
     */
    public C getCore() {
        return this.core;
    }

    /**
     * @return
     */
    protected M getModel() {
        return this.model;
    }

}
